# Data Processing Agreement — template

**Template, not legal advice.** Adapt it to the applicable law and have it
reviewed by a lawyer before signing. Fields in `[ ]` must be filled in.

## 1. Parties

- **Controller:** [COMPANY NAME], registered office [ ], VAT no. [ ],
  represented by [ ].
- **Processor:** [COMPANY NAME], registered office [ ], VAT no. [ ],
  represented by [ ].

## 2. Subject and duration

The Processor processes the personal data necessary to [install/manage/
support] the Aegis deployment at the Controller, for the duration of the
contract [X] and until return/deletion of the data.

## 3. Roles and instructions

The Controller is the data controller. The Processor processes data only on
documented instructions from the Controller, except where required by law. The
initial instructions are in Annex A (data categories, purposes, retention).

The Processor informs the Controller immediately if an instruction breaches
applicable law.

## 4. Confidentiality

Authorised personnel are bound by confidentiality, receive minimum access and
training, and use named credentials. Remote access is logged and revocable.

## 5. Security measures

At a minimum:

- encryption in transit (TLS; mTLS for agents in production);
- encryption of backups and credentials;
- RBAC, strong authentication for administrators and audit logging;
- segregation of environments and of Kraken data;
- minimisation, retention and verifiable deletion;
- incident and vulnerability management;
- no secrets or unnecessary personal data in logs.

## 6. Sub-processors

The Processor does not appoint sub-processors without the Controller's written
authorisation. Authorised: [LIST; "none" if not applicable]. Equivalent
obligations apply to each of them; the Processor remains liable to the
Controller.

## 7. Transfers

Data stays in the Controller's on-premise deployment. Any transfers outside the
EU require a written instruction, a legal basis and appropriate safeguards
(SCCs/adequacy decision). Optional cloud providers: [NONE / LIST].

## 8. Assistance

The Processor assists the Controller, as far as possible, in responding to data
subject requests, in impact assessments and in consultations with the
authority. Requests must be sent to [PRIVACY CONTACT] within [5] working days.

## 9. Data breach

The Processor notifies the Controller without undue delay and in any case
within **24 hours** of confirmation, including:

- nature of the event and affected data categories;
- hosts/users and estimated volume;
- containment measures taken;
- residual risk and recommendations.

The Controller decides on notification to the authority within 72 hours, unless
the law requires otherwise.

## 10. Return and deletion

On termination the Processor returns the data in [JSON/SQL/other] format and
deletes the data held in its systems within [30] days, except where retention is
mandatory. Backups rotate within [7] days. Deletion is certified in writing;
immutable security copies may remain until retention expires.

## 11. Audit

The Controller may verify compliance with the DPA through a
[questionnaire/audit] with [10] days' notice, without accessing other customers'
data. The Processor provides evidence of configuration, backup/restore and
audit.

## 12. Liability and applicable law

Liability: [LIMITS CONSISTENT WITH THE MAIN CONTRACT]. Law: [LAW]. Venue:
[VENUE]. In the event of conflict between the DPA and the main contract, the
DPA prevails for the processing of personal data.

## Annex A — Processing details

| Item | Value |
|---|---|
| Categories of data subjects | Employees, contractors, endpoint users, external attackers (Kraken) |
| Categories of data | Identifiers, endpoint telemetry, logs, attempted credentials, malware samples |
| Purposes | Information security, incident detection and response |
| Retention | Telemetry 14 days; alerts 90 days; audit 365 days; syslog 30 days; Kraken 30 days/5 GiB; backups 7 days |
| Location | [COUNTRY/DATA CENTER] |
| Sub-processors | [NONE / LIST] |
| Additional measures | [mTLS, Kraken isolation, backup encryption, minimum access] |

Signatures:

Controller ____________________  Date ________

Processor ________________  Date ________
