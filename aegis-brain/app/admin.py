"""CLI operativa di Aegis-Brain — gira **fuori** dal processo HTTP.

Perché esiste questo modulo
---------------------------
Il modello RBAC è applicato in una decina di endpoint (`admin`, `analyst`,
`responder`), ma nessuna rotta HTTP crea o modifica un utente privilegiato.
Non è una dimenticanza ed è voluto: **un privilegio non si concede da una API
esposta**, si concede da una shell sull'host, e resta tracciato nell'audit.

Conseguenza pratica: su un deployment nuovo il primo utente registrato è
`user`, e senza questo comando le funzioni privilegiate (isolamento host,
approvazione deploy, cancellazione regole/alert, assegnazione site) sono
irraggiungibili. Il percorso zero-config è `bootstrap` (registra se serve e
promuove in un colpo solo); `set-role` serve per cambi ruoli successivi.

Il ruolo è riletto dal DB a ogni richiesta (`core.deps._validate_token`), quindi
il cambio ha effetto immediato: **nessun re-login necessario**.

Uso (dentro il container):
    docker exec aegis-brain python -m app.admin list
    docker exec aegis-brain python -m app.admin bootstrap <email> <password>
    docker exec aegis-brain python -m app.admin set-role <email> analyst

`set-role` rifiuta di togliere l'ultimo admin rimasto (usa `--force` per
forzare, consapevolmente).
"""
from __future__ import annotations

import argparse
import asyncio
import sys

from sqlalchemy import select

from app.core.audit import log_audit
from app.core.deps import KNOWN_ROLES
from app.core.security import hash_password, verify_password
from app.database.connection import AsyncSessionLocal, engine
from app.database.models import User

# Unica fonte di verita': la matrice ruoli→permessi in core.deps. Se un ruolo
# viene aggiunto li', questo CLI lo accetta senza modifiche.
ROLES = KNOWN_ROLES
ACTOR = "aegis-brain:cli"


async def _list() -> int:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(User).order_by(User.id))).scalars().all()
        if not rows:
            print("nessun utente: registrane uno dalla UI, poi promuovilo qui")
            return 0
        print(f"{'id':>4}  {'ruolo':<10} {'attivo':<7} email")
        for u in rows:
            print(f"{u.id:>4}  {u.role:<10} {str(bool(u.active)):<7} {u.email}")
        admins = [u for u in rows if (u.role or "") == "admin"]
        print(f"\nadmin: {len(admins)}")
        if not admins:
            print("ATTENZIONE: nessun admin. Le funzioni privilegiate sono "
                  "irraggiungibili finché non esegui set-role.")
        return 0


async def _set_role(email: str, role: str, force: bool) -> int:
    role = role.lower().strip()
    if role not in ROLES:
        print(f"ruolo non valido: {role!r} (ammessi: {', '.join(ROLES)})", file=sys.stderr)
        return 2
    async with AsyncSessionLocal() as db:
        user = (await db.execute(
            select(User).where(User.email == email))).scalars().first()
        if not user:
            print(f"utente non trovato: {email}", file=sys.stderr)
            return 1

        previous = user.role or "user"
        if previous == role:
            print(f"{email}: gia {role}, nessuna modifica")
            return 0

        if previous == "admin" and role != "admin":
            others = (await db.execute(
                select(User).where(User.role == "admin", User.id != user.id)
            )).scalars().all()
            if not others and not force:
                print(
                    "rifiutato: e' l'ultimo admin. Promuovi qualcun altro prima, "
                    "oppure usa --force (deployment senza amministratore).",
                    file=sys.stderr)
                return 1

        user.role = role
        await log_audit(
            db, action="user_role_change", resource="user",
            resource_id=str(user.id), username=ACTOR,
            details={"email": email, "from": previous, "to": role, "via": "cli"},
        )
        await db.commit()
        print(f"{email}: {previous} -> {role} (audit registrato)")
        return 0


async def _create_user(username: str, email: str, password: str, role: str) -> int:
    role = role.lower().strip()
    if role not in ROLES:
        print(f"ruolo non valido: {role!r} (ammessi: {', '.join(ROLES)})", file=sys.stderr)
        return 2
    if len(password) < 8:
        print("password troppo corta (minimo 8 caratteri)", file=sys.stderr)
        return 2
    async with AsyncSessionLocal() as db:
        for column, value in ((User.email, email), (User.username, username)):
            if (await db.execute(select(User).where(column == value))).scalars().first():
                print(f"gia esistente: {value}", file=sys.stderr)
                return 1
        user = User(username=username, email=email,
                    password_hash=hash_password(password), role=role)
        db.add(user)
        await log_audit(
            db, action="user_create", resource="user", username=ACTOR,
            details={"email": email, "username": username, "role": role, "via": "cli"},
        )
        await db.commit()
        await db.refresh(user)
        print(f"creato id={user.id} {email} ruolo={role}")
        return 0


async def _bootstrap(email: str, password: str) -> int:
    """Percorso zero-config: l'utente diventa admin in un solo comando.

    Risolve il chicken-and-egg del deployment fresco (con ALLOW_OPEN_REGISTRATION
    attivo l'utente puo' registrarsi dalla UI, ma nasce `user`): un solo comando
    lo registra (se serve) e lo promuove. Idempotente: se l'utente esiste gia'
    verifica solo la password e promuove. Se password errata -> rifiuta (non e'
    un reset di credenziali: per quello c'e' set-role su un account noto).
    """
    if len(password) < 8:
        print("password troppo corta (minimo 8 caratteri)", file=sys.stderr)
        return 2
    async with AsyncSessionLocal() as db:
        user = (await db.execute(
            select(User).where(User.email == email))).scalars().first()
        if user:
            if not verify_password(password, user.password_hash):
                print(f"rifiutato: esiste un account con email {email} ma la "
                      "password non corrisponde. Usa set-role su un account di "
                      "cui conosci le credenziali.", file=sys.stderr)
                return 1
            created = False
        else:
            username = email.split("@")[0][:150]
            user = User(username=username, email=email,
                        password_hash=hash_password(password), role="user",
                        active=True)
            db.add(user)
            await db.flush()
            created = True

        previous = user.role or "user"
        user.role = "admin"
        await log_audit(
            db, action="user_bootstrap", resource="user",
            resource_id=str(user.id), username=ACTOR,
            details={"email": email, "created": created,
                     "from": previous, "to": "admin", "via": "cli"},
        )
        await db.commit()
        verb = "creato e promosso" if created else "promosso"
        print(f"[ok] {email}: {verb} ad admin (audit registrato). "
              "Accedi dalla UI con questa email.")
        return 0


async def _run(args) -> int:
    try:
        if args.command == "list":
            return await _list()
        if args.command == "set-role":
            return await _set_role(args.email, args.role, args.force)
        if args.command == "create-user":
            return await _create_user(
                args.username, args.email, args.password, args.role)
        if args.command == "bootstrap":
            return await _bootstrap(args.email, args.password)
    finally:
        await engine.dispose()
    print("comando non riconosciuto", file=sys.stderr)
    return 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.admin",
        description="Operazioni amministrative Aegis-Brain (fuori dal processo HTTP).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="elenca utenti, ruoli e numero di admin")

    p_role = sub.add_parser("set-role", help="cambia il ruolo di un utente")
    p_role.add_argument("email")
    p_role.add_argument("role", help=f"uno di: {', '.join(ROLES)}")
    p_role.add_argument("--force", action="store_true",
                        help="permetti di togliere l'ultimo admin")

    p_create = sub.add_parser("create-user", help="crea un utente con ruolo esplicito")
    p_create.add_argument("username")
    p_create.add_argument("email")
    p_create.add_argument("password")
    p_create.add_argument("--role", default="user", help=f"uno di: {', '.join(ROLES)}")

    p_boot = sub.add_parser(
        "bootstrap",
        help="percorso zero-config: registra (se serve) e promuove ad admin")
    p_boot.add_argument("email")
    p_boot.add_argument("password")

    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
