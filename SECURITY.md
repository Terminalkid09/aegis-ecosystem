# Security policy

## Supported versions

Aegis has no stable production release yet. The first supported line will be
**4.1.x**. The `dev` and `main` branches are development branches and are not
supported for production use.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:

<https://github.com/Terminalkid09/aegis-ecosystem/security/advisories/new>

If private reporting is not available, open an issue titled
`Security contact requested` **without technical details**; the maintainer will
open a private channel.

Do **not** open a public issue containing a reproducer, exploit, credentials,
customer data or live malware.

Please include:

- version or commit, component and platform;
- minimal reproduction and observed impact;
- whether the issue is already public;
- a suggested fix, if you have one;
- whether you want credit.

## What to expect

- Solo maintainer, best effort. There is no 24/7 support, no SLA and no bug
  bounty.
- Acknowledgement target: 5 business days. Triage target: 10 business days.
- Reporters are credited unless they ask otherwise.
- Fix priority follows severity; critical issues come first.

## Scope

In scope: `aegis-brain`, `aegis-guard`, `aegis-link`, `NodeTrace`,
`aegis-ebpf`, `frontend`, the deployment manifests, and `services/kraken`
once imported.

Out of scope: vulnerabilities in third-party dependencies (report them
upstream), social engineering, physical attacks, denial of service, spam,
scanner noise without a concrete impact, and missing hardening headers without
a demonstrated scenario.

## Safe harbor

Good-faith research is welcome if you:

- test only systems you own or have explicit permission to test;
- do not access, modify or exfiltrate data that is not yours;
- do not degrade a production service;
- give the maintainer reasonable time to fix the issue before publication.

This policy does not authorize testing of third-party systems.
