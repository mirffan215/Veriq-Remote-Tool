# Deploying with Microsoft Intune

Targets Windows 11. Assumes you have a code-signing certificate (BUILD.md → *Code signing*). **Never deploy an unsigned build** — `deploy/intune/install.ps1` refuses to.

## 1. Build, sign, package
```powershell
./scripts/publish-app.ps1                                              # tests + single-file exe
./scripts/sign-app.ps1 -File artifacts\app\RemoteTool.exe -Thumbprint <SHA1>   # or -PfxPath / Azure Trusted Signing
./scripts/package-intune.ps1 -IntuneWinAppUtil C:\tools\IntuneWinAppUtil.exe    # -> artifacts\intune\install.intunewin
```
`package-intune.ps1` copies the signed exe plus `deploy/intune/{install,uninstall,detect}.ps1` and bakes the exe's SHA-256 into the detection script.

## 2. Create the Win32 app
| Field | Value |
|---|---|
| Install command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1` |
| Uninstall command | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1` |
| Install behaviour | **System** |
| Requirements | Windows 11 (build ≥ 22000), 64-bit |
| Detection | Custom script → `detect.ps1` (checks path, valid signature, SHA-256) |
| Assignment | *Required* to the PC groups that need it; keep unattended PCs in a **separate** group/app |

## 3. Two flavours
* **Attended (default, all employee PCs)**: the app is just copied; each user starts it. Relay settings reach users through machine environment variables the script sets
  (`REMOTETOOL_RELAY`, optional `REMOTETOOL_RELAY_FP`); the relay *access key* should be delivered with `REMOTETOOL_RELAY_KEY` by a **Proactive Remediation / platform script** that reads it
  from your secret store, not hard-coded in the package. The app stores it DPAPI-protected after first launch.
* **Unattended (servers, kiosks, lab PCs)**: set `$UnattendedPC = $true` in your *private* copy of `install.ps1`; supply `RT_RELAY_KEY` and `RT_PERMANENT_PASSWORD` as environment variables from your
  secret store (Intune script contents are visible to Intune administrators — treat them as such). Use a **different permanent password per PC or per group**, ≥12 chars. After install, hand the PC's
  ID (shown in the setup window, or `%ProgramData%\RemoteTool\public\service-status.json`) to your inventory.

## 4. Defender, AppLocker, WDAC, SmartScreen
1. **Defender for Endpoint → Settings → Indicators → Certificates**: add your signing certificate as *Allow*. This is better than file hashes (which change every release).
2. **Defender Antivirus exclusions**: none should be needed for a signed build. If the behavioural “CreateProcessAsUser from service” rule fires on the helper launch, add a *process* exclusion for `%ProgramFiles%\RemoteTool\RemoteTool.exe` only.
3. **AppLocker / WDAC**: create a *publisher* rule for your certificate (product `REMOTETOOL`), not a path rule. Remember the service executes from Program Files and the helper from the same path.
4. **SmartScreen**: a new/rare file may be warned about until it builds reputation; an EV certificate or Azure Trusted Signing avoids the warm-up. Files *received* through RemoteTool are tagged as downloaded (Zone 3).
5. Tell your SOC: the tool, the relay host name(s), and the two audit events that matter — `unattended_breaker_tripped` and `source_blocked`.

## 5. Updates
Re-run the pipeline with a higher `<Version>` (Directory.Build.props), re-sign, re-package, supersede the old app. `install.ps1` stops nothing by itself; for unattended PCs the installer's
`--configure-service` stops the service, replaces the exe and restarts it. Keep the previous package for rollback.

## 6. Uninstall / offboarding
`uninstall.ps1` removes the service and the program folder but **keeps** `%ProgramData%\RemoteTool` (audit logs, recordings) for your retention period. Delete it afterwards per policy.
