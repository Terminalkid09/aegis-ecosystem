# Aegis — Secrets (files, Docker/Kubernetes and Vault)

Aegis does not require secrets to live in a committed `.env` file or a public CI
variable. The Brain resolves secret sources **before** constructing `Settings`
(`app/core/secrets.py`).

## 1. Precedence

1. `NAME_FILE` (the file wins over an existing `NAME` variable: mounting a
   secret is an explicit deployment decision).
2. `AEGIS_SECRETS_DIR`: a directory with one file per variable, for example
   `/run/secrets/aegis/JWT_SECRET`.
3. HashiCorp Vault KV v2, only when `AEGIS_VAULT_ENABLED=true`. It fills
   variables that are still missing; `AEGIS_VAULT_OVERRIDE=true` is the only
   exception.

A missing, empty or unreadable file is a startup error. There is no silent
fallback to a default value.

## 2. File secrets (Docker/Kubernetes)

```bash
install -d -m 700 /etc/aegis/secrets
printf '%s' "$(openssl rand -hex 32)" > /etc/aegis/secrets/JWT_SECRET
chmod 600 /etc/aegis/secrets/JWT_SECRET
```

Mount the directory in the container and set:

```yaml
environment:
  AEGIS_SECRETS_DIR: /run/secrets/aegis
volumes:
  - /etc/aegis/secrets:/run/secrets/aegis:ro
```

Or use one file per secret:

```yaml
environment:
  JWT_SECRET_FILE: /run/secrets/jwt_secret
  DATABASE_URL_FILE: /run/secrets/database_url
  MASTER_KEY_B64_FILE: /run/secrets/master_key_b64
```

Files contain **only** the value, without `NAME=`. The repository compose mounts
`./secrets` at `/run/secrets` (read-only) and sets
`AEGIS_SECRETS_DIR=/run/secrets`; create `secrets/JWT_SECRET`,
`secrets/MASTER_KEY_B64`, and so on. The directory is git-ignored. Files win
over variables already present in the container; Vault only fills missing ones.
For Docker Compose, remember that compose interpolation happens before the
container starts: in production, also use an orchestrator that injects files
(Kubernetes Secrets, Docker Swarm secrets, systemd `LoadCredential`) or a
protected `env_file` containing only non-secret variables. Do not use a public
`.env` for secrets.

## 3. HashiCorp Vault KV v2

```bash
vault kv put secret/aegis/prod \
  JWT_SECRET="$(openssl rand -hex 32)" \
  AEGIS_API_KEY="$(openssl rand -hex 32)" \
  AGENT_ENROLL_KEY="$(openssl rand -hex 16)" \
  MASTER_KEY_B64="$(openssl rand -base64 32)" \
  POSTGRES_PASSWORD="$(openssl rand -hex 24)" \
  REDIS_PASSWORD="$(openssl rand -hex 24)"
```

Configuration:

```dotenv
AEGIS_VAULT_ENABLED=true
AEGIS_VAULT_ADDR=https://vault.example.internal
AEGIS_VAULT_MOUNT=secret
AEGIS_VAULT_PATH=aegis/prod
AEGIS_VAULT_TOKEN_FILE=/run/secrets/vault_token
# AEGIS_VAULT_NAMESPACE=team-a
# AEGIS_VAULT_CACERT=/etc/ssl/certs/internal-ca.pem
```

The Vault token must be read-only on the path. Never put it in `.env`, shell
history or logs. `AEGIS_VAULT_SKIP_VERIFY=true` exists only for a lab with a
self-signed CA and must not be used in production.

## 4. Admin bootstrap without a persisted password

`setup.py` generates the first admin password, prints it **once**, and does not
write it to `.env`. For automation/CI, use a secret file:

```bash
export AEGIS_ADMIN_PASSWORD_FILE=/run/secrets/aegis_admin_password
python scripts/setup.py
```

Alternatively, create the admin from the host shell:

```bash
docker exec aegis-brain python -m app.admin bootstrap admin@aegis.local '<strong-password>'
```

Re-running `setup.py` does not reset an existing admin. The password remains
unchanged and the authenticated smoke test is skipped when the password is not
available. To rotate it, use `python -m app.admin` or the **Users & Roles** page.

## 5. Real verification (2026-11-20)

In addition to unit tests, the following real tests were executed:

- **File secrets**: temporary directory, file precedence over a plain variable,
  `NAME_FILE`, and explicit failure on an empty file;
- **HashiCorp Vault KV v2**: Vault 1.18 dev, secret written through the API and
  read by the real resolver; variables already present in the environment were
  not overwritten; path and token were required, and an error never became a
  silent default.

The tests never print secret values; output contains only the names of the
loaded variables.

## 6. Public CI

This repository's CI is public and must not contain secrets. Deployment
credentials come from a protected environment (GitHub Environments, Vault/OIDC
federation, the orchestrator's secret manager), never from a versioned file.
`.env.example` contains placeholders, and the production validator rejects the
`change-me`/`replace-with` markers.
