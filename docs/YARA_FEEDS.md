# Aegis — Signed YARA feeds

Version 1.0 — 2026-11-20.

Aegis can update YARA signatures automatically, but only from a feed the
operator owns and signs. It is **not** a vendor malware-research subscription:
the update mechanism is real; the rule content and its licensing remain a
deployment responsibility.

## 1. Security model

A bundle is imported only if all of these are true:

1. the URL is configured in `YARA_FEED_URLS` and uses HTTPS (HTTP is allowed
   only for explicit localhost tests);
2. the response body has a valid Ed25519 signature from
   `YARA_FEED_PUBLIC_KEY_B64`;
3. the JSON matches `aegis-yara-feed/v1`;
4. every rule compiles with `yara-python` in the Brain;
5. no rule name collides with a manual rule or another feed.

A failure changes nothing. The previous rules stay active; the error is stored
in `yara_feed_state` and shown in **YARA & FIM → Signed signature feeds**.
There is no unsigned fallback and no “last known good download from an
arbitrary URL”.

## 2. Bundle format

The signature is detached: Ed25519 over the exact bytes of the response body.
The HTTP response carries:

```text
X-Aegis-Signature: <base64(64-byte Ed25519 signature)>
X-Aegis-Key-Id: <optional key id>
Content-Type: application/json
```

`feed.json`:

```json
{
  "format": "aegis-yara-feed/v1",
  "feed_id": "soc-lab",
  "version": "2026.11.20.1",
  "rules": [
    {
      "name": "Soc_Lab_Ransomware_Note",
      "content": "rule Soc_Lab_Ransomware_Note { strings: $s = \"YOUR FILES ARE ENCRYPTED\" condition: $s }",
      "severity": "high",
      "description": "Ransom note observed in the lab",
      "tags": ["ransomware", "note"],
      "mitre": "T1486"
    }
  ]
}
```

Limits: 5,000 rules per bundle, 64 KiB per rule, 1,000 characters per
description, 20 tags, 8 MiB default body (`YARA_FEED_MAX_BYTES`). `severity` is
one of `low`, `medium`, `high`, `critical`. `mitre` is `T1234` or `T1234.001`.

## 3. Generate a key and sign a bundle

Generate the key once, offline. Keep the private key out of the repository and
out of the Brain container; only the public key is configured.

```bash
python - <<'PY'
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
priv = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
pub = key.public_key().public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw,
)
open("yara-feed-private.pem", "wb").write(priv)
print("YARA_FEED_PUBLIC_KEY_B64=" + base64.b64encode(pub).decode())
PY
```

Sign the exact file that the feed server will return:

```bash
python - <<'PY'
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key

body = open("feed.json", "rb").read()
key = load_pem_private_key(open("yara-feed-private.pem", "rb").read(), password=None)
print(base64.b64encode(key.sign(body)).decode())
PY
```

Serve `feed.json` with the signature in `X-Aegis-Signature`. The Brain does not
follow redirects and rejects non-200 responses.

## 4. Configuration

```env
YARA_FEED_ENABLED=true
YARA_FEED_URLS=https://feeds.example.com/aegis/feed.json
YARA_FEED_PUBLIC_KEY_B64=<base64 raw public key>
YARA_FEED_KEY_ID=prod-2026-11
YARA_FEED_INTERVAL_S=3600
YARA_FEED_TIMEOUT_S=20
YARA_FEED_MAX_BYTES=8388608
YARA_FEED_ALLOW_HTTP=false
```

`YARA_FEED_ENABLED=true` without a URL or a decodable 32-byte public key is a
startup error: a feed cannot be half-configured.

The Brain starts a scheduler after startup and checks every
`YARA_FEED_INTERVAL_S` (minimum 60 s). Multiple uvicorn workers coordinate with
a PostgreSQL advisory lock, so one sync runs at a time. An administrator can
force a checked sync from the UI or:

```bash
curl -X POST https://<domain>/api/v1/yara/feeds/sync \
  -H "Authorization: Bearer <admin-token>"
```

The endpoint never accepts a URL or an unsigned body.

## 5. Update semantics

- A new rule is inserted with `source=feed:<feed_id>`, `managed=true`,
  `source_version`, checksum and metadata.
- An existing rule from the same feed is updated (content, severity, tags,
  description, MITRE, checksum).
- A rule no longer present in the bundle is **deactivated**, not deleted, so old
  findings remain attributable.
- A name collision with a manual rule or another feed rejects the whole bundle.
  This prevents one feed from silently replacing another team's signature.
- Feed-managed rules are read-only in the API except for the `is_active`
  toggle; a later sync re-enables them. Remove or change the rule in the feed
  instead.
- The Aegis Total cache includes the active-rule fingerprint: an updated rule
  invalidates an old report instead of leaving a stale verdict.

## 6. What this is not

- It does not generate signatures automatically. A false positive or a new
  family still needs a rule author, testing and a signed bundle.
- It does not replace a commercial AV engine, a sandbox or a threat-intel
  subscription. It is a controlled delivery path for YARA rules.
- It does not make the endpoint tamper-proof. A local administrator can still
  stop the agent; see `KERNEL_AND_DRIVERS.md`.
- It does not remove the need to review feed licensing and rule quality. The
  Ed25519 signature proves origin and integrity, not correctness.

## 7. Tests

The offline tests are in `aegis-brain/tests/test_yara_feed.py`:

- valid signed bundle imports provenance;
- tampered body is rejected and changes nothing;
- unsigned bundle is rejected;
- a feed cannot overwrite a manual rule;
- removed rules are deactivated;
- malformed/HTTP URLs are rejected.

On Python 3.15, where `yara-python` has no wheel, the DB/signature tests use a
fake compiler and the real-compiler test is skipped. The `yara_engine` CI job
on Python 3.12 runs the real engine.
