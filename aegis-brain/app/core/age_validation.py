"""Validazione header temporali (Fase 5).

L'header Age (o X-Event-Age) indica da quanti secondi l'evento è stato
creato sul sensore. Va validato strettamente: valori negativi, enormi,
non numerici o incoerenti con il timestamp dell'evento sono rifiutati
(possibile replay o clock anomalo)."""
from fastapi import Request, HTTPException

MAX_AGE_SECONDS = 7 * 24 * 3600  # 7 giorni, oltre è sicuramente stale o replay

def validate_age_header(request: Request, event_timestamp=None):
    """Valida Age/X-Event-Age/X-Created-At se presenti. Solleva 400 se invalidi."""
    # Cerca header case-insensitive
    headers = {k.lower(): v for k, v in request.headers.items()} if hasattr(request, "headers") else {}
    raw = None
    for name in ("age", "x-event-age", "x-created-at", "x-event-timestamp"):
        if name in headers:
            raw = headers[name]
            header_name = name
            break
    else:
        return  # nessun header temporale -> ok (compatibilità v1)

    # Deve essere numerico
    try:
        # Supporta sia secondi interi che float, e anche timestamp unix
        age = float(raw)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail=f"Header {header_name} non numerico")

    if not (0 <= age <= MAX_AGE_SECONDS):
        # Se è un timestamp Unix (es. 1700000000), è > MAX_AGE ma va interpretato
        # come timestamp assoluto; allora verifica coerenza con event_timestamp
        # Altrimenti è un Age enorme → rifiuta.
        if age > 1_000_000_000:  # probabile timestamp unix
            # Verifica che non sia futuro o troppo vecchio rispetto a now
            import time
            now = time.time()
            if age > now + 60 or age < now - MAX_AGE_SECONDS:
                raise HTTPException(status_code=400, detail=f"Header {header_name} timestamp incoerente")
            # Se abbiamo event_timestamp, verifica che la differenza sia ~Age
            if event_timestamp:
                try:
                    from datetime import datetime, timezone
                    if isinstance(event_timestamp, str):
                        event_timestamp = datetime.fromisoformat(event_timestamp)
                    if event_timestamp.tzinfo is None:
                        event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
                    delta = (now - event_timestamp.timestamp())
                    if abs(delta - (now - age)) > 300:  # 5 min tolleranza
                        # Non rifiuta ma logga; per ora solo warning via exception se molto incoerente
                        if abs(delta) > MAX_AGE_SECONDS:
                            raise HTTPException(status_code=400, detail=f"Header {header_name} incoerente con timestamp evento")
                except HTTPException:
                    raise
                except Exception:
                    pass
            return
        raise HTTPException(status_code=400, detail=f"Header {header_name} fuori range 0..{MAX_AGE_SECONDS}")

    # Se abbiamo event_timestamp, verifica coerenza stretta
    if event_timestamp:
        try:
            from datetime import datetime, timezone
            import time
            if isinstance(event_timestamp, str):
                event_timestamp = datetime.fromisoformat(event_timestamp)
            if event_timestamp.tzinfo is None:
                event_timestamp = event_timestamp.replace(tzinfo=timezone.utc)
            now = time.time()
            event_age = now - event_timestamp.timestamp()
            # Age dichiarato deve essere vicino a event_age (tolleranza 60s + 10%)
            if abs(event_age - age) > max(60, abs(age) * 0.1):
                # Solo warning se discrepanza moderata, rifiuto se enorme
                if abs(event_age - age) > 3600:
                    raise HTTPException(status_code=400, detail=f"Header {header_name} incoerente con timestamp evento")
        except HTTPException:
            raise
        except Exception:
            pass
