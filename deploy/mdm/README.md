# MDM / Intune / GPO deployment contract

Status: **templates, not tenant evidence.** These files show the supported
Windows lifecycle; a real Intune tenant or GPO domain is still required to
validate assignment, detection, upgrade and uninstall on managed endpoints.
The repository does not contain a tenant ID, client secret, enrollment token or
code-signing certificate.

## What the MSI provides

- installs `aegis-agent.exe` under `C:\Program Files\Aegis`;
- registers the `AegisAgent` service;
- sets `AEGIS_AGENT_PROFILE=unified`, `AEGIS_AGENT_MODE=full`,
  `AEGIS_BRAIN_URL`, `AEGIS_IDENTITY_DIR` and `AEGIS_ENROLL_TOKEN_FILE`;
- accepts `BRAIN_URL=...` as a public MSI property;
- never embeds an enrollment token.

The token is short-lived and single-use. Create it in Deployment Manager for
**AegisAgent (unified)**, then deliver it out-of-band (Intune script parameter,
GPO file preference, or a secret-management step). Do not put it in the MSI,
the Intune app description, a script argument, or source control.

## Intune

Use one of these two supported paths:

1. **Line-of-business MSI** — upload the production-signed MSI, set
   `BRAIN_URL=https://aegis.example.com` in the MSI command line, assign to a
   pilot group, and use `Detect-Aegis.ps1` as a custom detection rule.
2. **Win32 app** — package the MSI with `Install-Aegis.ps1`,
   `Detect-Aegis.ps1` and `Uninstall-Aegis.ps1` via the Microsoft Win32 Content
   Prep Tool. `Install-Aegis.ps1` accepts `-EnrollTokenFile`; the file must be
   provided by a protected Intune script/secret step, not committed here.

`Install-Aegis.ps1` verifies the Authenticode status is `Valid` before running
`msiexec`. A test-signed certificate (`UnknownError` on an untrusted machine)
is intentionally rejected. It installs with `/qn /norestart`, provisions the
token with an ACL limited to SYSTEM and Administrators, then starts
`AegisAgent`. If no token is supplied it leaves the service stopped, so a
missing token is visible rather than a false successful enrollment.

`Detect-Aegis.ps1` exits 0 only when the service exists and is running. That
means a stopped service is remediated by Intune instead of being reported as
healthy. `Uninstall-Aegis.ps1` resolves the MSI product code from the uninstall
registry entry; it does not delete `C:\ProgramData\Aegis` state by default.

## GPO

For a domain-joined fleet, publish the production-signed MSI as a **Computer
Configuration → Software Installation** package (assigned), with a transform
or MST that sets `BRAIN_URL`. Deliver the token with a **File Preference** to
`C:\ProgramData\Aegis\enroll.token` (SYSTEM/Administrators only) or with a
startup script that calls `Install-Aegis.ps1`. Do not use a user-context GPO:
the service runs as LocalSystem and the machine environment is what the agent
reads.

Validation on a clean managed host:

```powershell
.\Validate-Aegis.ps1 -MsiPath .\aegis-agent-4.3.0-x64.msi `
  -ExpectedVersion 4.3.0
```

The output is JSON. It reports `tenant_validation: "not_performed"` on purpose:
only the operator's Intune/GPO tenant can prove assignment and policy
propagation. It does verify the local signature, service, binary version and
token ACL.

## What must be captured for release evidence

| Evidence | Where |
|---|---|
| Production Authenticode chain and timestamp | `Get-AuthenticodeSignature` on the MSI |
| Intune assignment/policy state | Intune portal export or Graph API |
| Clean-host install/detect/upgrade/uninstall | `Validate-Aegis.ps1` output |
| Token provisioned and consumed once | Deployment Manager/audit log |
| No token in package/description | `7z l`/MSI inventory + secret scan |

The `production_signing` workflow in `.github/workflows/packaging.yml` is the
CI path for a signed MSI; it consumes repository secrets in the protected
`production-signing` environment. This directory deliberately contains no
private key.
