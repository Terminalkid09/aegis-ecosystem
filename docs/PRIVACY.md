# Privacy and GDPR — Aegis Ecosystem

Status: technical draft for Gate 0 (AP-20), 2026-11-15. **This is not legal
advice.** Before distribution to customers, the document and the DPA must be
reviewed by a competent lawyer/DPO.

Aegis is distributed on-premise: the customer who installs the platform decides
why and how data is processed. The project does not run a SaaS service and does
not receive telemetry from customer deployments.

## 1. Roles

| Scenario | Controller | Processor | Notes |
|---|---|---|---|
| Customer installs Aegis on its own endpoints | Customer | Customer (or the customer's IT provider) | The project does not process the data |
| IT provider installs and manages Aegis for a customer | Customer | IT provider | A DPA between customer and provider is required |
| Remote maintenance of the deployment | Customer | Party accessing under authorisation | Minimum access, logged and revocable |

The software vendor is not a processor merely because the code is installed.
Any remote support must be covered by a separate agreement and by traced
access.

## 2. Processing register

| Data | Purpose | Legal basis (indicative) | Default retention | Where |
|---|---|---|---|---|
| Endpoint telemetry: processes, paths, hashes, usernames, commands, network | Security incident detection and response | Legitimate interest in security; legal obligations where applicable | 14 days | PostgreSQL `telemetry` |
| Alerts, incidents, timeline, analyst notes | Triage and response | Security; legal obligations | 90 days | PostgreSQL `alerts`, `incidents` |
| Audit log of access and actions | Accountability and investigations | Security obligations; legitimate interest | 365 days | PostgreSQL `audit_logs` |
| Syslog | Security correlation | Legitimate interest | 30 days | PostgreSQL `syslog_events` |
| Agent credentials (device secret) | Endpoint authentication | Contract performance/security | Until revocation | Hash in PostgreSQL; Redis cache stores hashes only |
| Enrollment tokens | Host registration | Security | 15 minutes, single use | Hash in PostgreSQL |
| VaultX notes | Customer operational secrets | Contract performance | Until deletion | Encrypted PostgreSQL |
| Backups | Operational continuity and recovery | Security | 7 days | Encrypted backup volume |
| Kraken: attack events, IPs, attempted usernames/passwords, commands | Analysis of attacks against honeypots | Legitimate interest in security | 30 days / 5 GiB quota | Separate Kraken instance |
| Kraken: uploaded malware samples | Technical analysis | Security; customer consent for unnecessary data | 30 days / 5 GiB quota | Separate sample archive |

The fields "username", IP addresses, hostname and command line can identify
natural persons. They are therefore not "non-personal data" merely because they
are technical.

## 3. Minimisation and logs

- Do not record passwords, tokens, API keys or file contents in application
  logs.
- Passwords attempted against Kraken are stored only as a keyed HMAC; the
  plaintext value is never written to the DB, JSONL, SIEM or Telegram alerts.
- Telemetry is configurable and can be reduced by the customer; retention is a
  maximum bound, not an obligation to keep everything.
- Kraken samples are accepted only within the limits on size, file count and
  quota; the content is never executed by the Brain.
- Debug logging must not be enabled in production (`DEBUG=false`).

## 4. Retention and deletion

Defaults:

- telemetry 14 days;
- alerts and incidents 90 days;
- audit 365 days;
- syslog 30 days;
- backups 7 days;
- Kraken 30 days and 5 GiB quota, with overwrite before unlink.

Retention is configurable, but it cannot be infinite by default. Purge must run
after a verified backup; the audit log is not deleted automatically without
explicit confirmation. On contract termination the customer can export and
delete the data of its own deployment. Backups rotate according to retention
and must be destroyed with the same procedure.

## 5. Residency and transfers

- The deployment is on-premise: data stays in the infrastructure chosen by the
  customer.
- No telemetry is sent to the project.
- Cloud AI providers are off by default and automatic enrichment is disabled;
  if the customer enables them, it must verify the provider's location and
  guarantees.
- Optional OSINT integrations send only indicators (IP/domain), not the full
  telemetry. The customer must still assess them in its own register.
- Backups must be stored in the jurisdiction required by the customer.

## 6. Data subject rights

The customer, as controller, handles access, rectification, erasure,
restriction, objection and portability. The deployment must allow at least:

- search and export of data by host/user and time range;
- deletion of data that is no longer necessary, subject to legal obligations
  and the chain of custody;
- anonymisation or pseudonymisation where security allows it.

Requests must be addressed to the deployment controller, not to the project.

## 7. Security

Measures present in, or required from, the deployment:

- TLS in transit; mTLS for agents in the prod profile;
- RBAC and action auditing;
- encryption of secrets and backups (GPG with an external passphrase);
- credential hashing and HMAC of attempted Kraken passwords;
- isolation of the Kraken sandbox and of the Docker broker;
- data minimisation and active retention;
- logs free of secrets and sensitive payloads.

## 8. Data breach

The deployment provider must have a procedure to:

1. contain and verify the event;
2. preserve evidence without collecting further data;
3. notify the controller without undue delay and in any case within 24 hours of
   confirmation, so that notification to the authority can be made within 72
   hours;
4. document impact, data categories, measures and communications.

The project receives vulnerability reports through `SECURITY.md`, not through
public issues containing personal data.

## 9. DPIA

Assess a DPIA when the deployment involves:

- systematic large-scale monitoring of employees;
- innovative or high-risk processing;
- special-category or judicial data;
- interconnection of sources or transfers outside the EU;
- automated decisions with significant effects.

The DPIA is the controller's responsibility; this draft provides the starting
inventory, not the conclusion.

## 10. Kraken: separation

Kraken is a distinct service with its own database and sample archive. It does
not share the Aegis database and must not be exposed on the same network as the
management instance. Attacker data is kept only for attack analysis, with
retention and quota, and must not be used for different purposes (for example
marketing or model training) without an independent legal basis.

## 11. Related documents

- [`DPA_TEMPLATE.md`](DPA_TEMPLATE.md)
- [`archive/TRADEMARK_RESEARCH.md`](archive/TRADEMARK_RESEARCH.md)
- [`OPERATIONS.md`](OPERATIONS.md) — retention and backups
- [`../SECURITY.md`](../SECURITY.md) — vulnerability reporting

## 12. Limits of this draft

It does not replace a signed processing register, a DPIA, legal advice or a
negotiated DPA. The default retention periods must be confirmed by the customer
and aligned with local obligations. Optional cloud integrations require a
separate assessment.
