# Required local secrets

Create `secrets/backup_passphrase` before starting the backup service:

```sh
umask 077
python -c "import secrets; print(secrets.token_urlsafe(48))" > secrets/backup_passphrase
```

The file is mounted read-only at `/run/secrets/backup_passphrase`; it must never
be committed. The backup and restore scripts fail closed without it.
