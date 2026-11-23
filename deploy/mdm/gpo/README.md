# GPO deployment notes

Use **Computer Configuration → Policies → Software Installation** with the
production-signed MSI. Assign it to a pilot OU first; do not publish it to all
computers until the pilot evidence is captured.

- Set `BRAIN_URL` with an MST or the package's public property. The MSI's
  default is `https://aegis.local`.
- Deliver `C:\ProgramData\Aegis\enroll.token` with a File Preference or a
  startup script. The directory and file must be readable only by SYSTEM and
  Administrators; the MSI's environment points at that exact path.
- Do not put the token in a GPO preference that is readable by users.
- Detection on the client is `Get-Service AegisAgent` plus the binary version;
  the Intune scripts in the parent directory are the same contract.
- Verify with `deploy/mdm/Validate-Aegis.ps1`; it does not claim tenant
  validation, only local post-deployment state.

Uninstall through **Software Installation** removes the service and binaries.
The state directory under `C:\ProgramData\Aegis` is retained unless an
operator explicitly removes it.
