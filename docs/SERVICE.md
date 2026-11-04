# Unattended access (Windows service)

Optional, **opt-in**, Windows 11 / Server 2022. Lets IT staff reach a PC with a *permanent password* — including at the login screen, on the lock
screen and across UAC prompts — without anybody clicking Allow. The normal (attended) mode is unchanged and remains the default.

## Architecture

```
 viewer ══ TLS1.3 e2e (same protocol v3) ══ relay ══ ┐
                                                      ▼
 ┌───────────────── RemoteTool.exe --service  (LocalSystem, session 0) ─────────────────┐
 │ ServiceRuntime ─ HostService (accepts ONLY permanent password + resume tickets)       │
 │   UnattendedPolicy  ─ "Winlogon" desktop ⇒ auto-allow ; user desktop ⇒ ask the user   │
 │   PipeFrameProducer / PipeInputInjector  ── local helper protocol ──┐                  │
 │   WindowsSasSender  (Ctrl+Alt+Del = SendSAS, service only)          │                  │
 └─────────────────────────────────────────────────────────────────────┼──────────────────┘
        WtsHelperLauncher: SYSTEM token duplicated, session id := console session,        │ named pipe, random name,
        CreateProcessAsUser                                                                ▼ ACL = SYSTEM only,
 ┌──────────── RemoteTool.exe --helper  (SYSTEM, in the console session) ────────────┐    client PID verified
 │ HelperEndpoint thread: attaches to the INPUT desktop (Default / Winlogon / UAC),  │
 │   GDI capture (+ H.264 via Media Foundation) and SendInput                         │
 │ WPF UI thread: red banner + Disconnect, emergency hotkey, consent dialog           │
 └────────────────────────────────────────────────────────────────────────────────────┘
```

* **One exe, three roles** (`--service`, `--helper`, normal). Installation copies it to `%ProgramFiles%\RemoteTool\` — a SYSTEM service must never run a binary from a
  user-writable folder, or any user could replace it and become SYSTEM. The installer sets a protected ACL (SYSTEM/Admins full, Users read+execute).
* **Why a SYSTEM token with a changed session id** (and not `WTSQueryUserToken`): at the login screen there is *no* user token, and a user-level process can never open the
  secure Winlogon desktop that shows UAC prompts and the lock screen. `WTSQueryUserToken` is only suitable for a "run as the logged-in user" helper; this design needs SYSTEM.
* **Service data** `%ProgramData%\RemoteTool\service\` (config, permanent-password key, audit log, recordings) is ACL’d to SYSTEM + Administrators. Only
  `%ProgramData%\RemoteTool\public\service-status.json` (ID, relay state, two booleans) is world-readable so the normal UI can show “managed by service”.
* The user-mode UI **steps aside** while the service runs: no second relay registration, no one-time password (it is disabled in service mode).

## What an unattended session may do

| Capability | Unattended | Why |
|---|---|---|
| View screen, mouse, keyboard | yes | purpose of the feature |
| Ctrl+Alt+Del | yes (service calls `SendSAS`) | needed for login/lock screen |
| Clipboard, file transfer | **no** | no person to confirm; the helper cannot safely touch the user's clipboard at the login screen |
| Secure desktop (UAC, lock, login) | yes | helper follows the input desktop |
| Recording | optional, off by default | see below |

## Controls (all on by default unless noted)
1. **Master switch** `UnattendedEnabled` (off until an admin enables it) *and* a stored permanent password; either missing ⇒ every unattended login fails like a wrong password.
2. **Permanent password**: ≥12 characters, ≥3 character classes. Stored only as `PBKDF2(password, salt, 600k)` protected with machine DPAPI in an ACL’d file. Same channel-bound
   proof as the one-time password; one try per connection; per-source lockout (5/15 min).
3. **Distributed-guessing breaker**: 20 failures from *any* sources within 15 min pause unattended logins for 15 min (audited as `unattended_breaker_tripped`). Operators are expected
   to alert on that event.
4. **Consent when a person is present** (`ConsentWhenUserPresent`, default **on**): if the input desktop is the user's desktop, the signed-in user gets the Allow/Deny dialog (60 s ⇒ deny).
   Only on the login/lock screen — nobody there — is the session auto-allowed. Disable only for kiosks/servers.
5. **Visible indicator**: red banner with Disconnect + Ctrl+Alt+Shift+Q on the user's desktop whenever a session runs (recording adds “● REC”). *It cannot be drawn on the secure
   desktop*; at the login screen there is nobody to see it, and the audit log is the record.
6. **Audit**: every decision is logged (`unattended_auto_allow`, `unattended_asking_user`, `unattended_denied`, `consent_granted unattended=True`, `special_key`, `helper_*`, `service_*`) to a hash-chained log.

## Install / configure / remove
* Interactive: *Allow Access → Unattended access (Windows service)…* (UAC prompt) → fill in relay, permanent password, switches → **Install / apply**.
* Headless (Intune/SCCM, elevated): `RemoteTool.exe --configure-service --relay r1:443,r2:443 --relay-fp <sha256> --relay-key-env RT_RELAY_KEY --password-env RT_PW --enable [--record] [--no-user-consent]`
  — secrets come from **environment variables**, never from arguments. Result log: `%ProgramData%\RemoteTool\configure-service.log`; exit code 0 = ok.
* Remove: setup window → **Uninstall service** (optionally purge data), or `sc stop/delete RemoteToolService`. Recordings and audit logs are kept unless purged.
* Service name `RemoteToolService`, start type delayed-auto, recovery: restart after 5 s / 5 s / 60 s.
* Inbound firewall: none needed with a relay (outbound 443/8443 only). If you enable the *direct listener* in the service config you must add your own inbound rule.

## Session recording (optional, off by default)
* Records **screen updates and coarse events only** — never keystrokes, clipboard or file contents. The consent dialog and viewer toolbar say so (“This session will be recorded”, “● REC”).
* Each record is AES-256-GCM encrypted with a per-file key wrapped by DPAPI (machine scope for the service); header and record counters are authenticated, so edits, reordering and
  gaps are detected. Retention default 30 days (auto-delete at service start). File name + SHA-256 are written to the audit log when a recording closes.
* Review: `RemoteTool.exe --export-recording file.rtrec <folder> --machine` (elevated, same PC) → PNGs every 5 s + `stream.h264`.
* Legal/HR: recording employees' screens is regulated (consent, notice, retention, access). Get sign-off before enabling it.

## Validation checklist — REQUIRED before production (not testable off-Windows)
The logic is covered by automated tests with a simulated helper; the following depend on real Windows behaviour and were **not run** by the author:
1. `scripts\validate-windows.ps1` on a disposable Windows 11 VM (elevated): all lines PASS.
2. From a second PC (viewer): connect with the permanent password **while the VM is at the login screen** → picture + keyboard works; type the account password and sign in.
3. With a user signed in: connect → the user sees the Allow dialog; Deny works; Allow shows the banner; Disconnect and Ctrl+Alt+Shift+Q work.
4. Trigger a **UAC prompt** (run something as admin): viewer sees the dimmed secure desktop and can click Yes; mouse/keyboard work.
5. **Ctrl+Alt+Del** toolbar button shows the secure-attention screen; **Win+L** lock → viewer still sees/controls the lock screen.
6. Fast user switching / RDP in/out / sign-out: helper follows (`helper_started` events), session resumes or ends cleanly, no stuck helper.
7. Verify the pipe ACL: as a standard user, `[IO.Directory]::GetFiles("\\.\pipe\")` shows `RemoteTool.Helper.*` but opening it fails with *Access denied*.
8. Standard user cannot modify `%ProgramFiles%\RemoteTool\RemoteTool.exe`, cannot read `%ProgramData%\RemoteTool\service\*`.
9. Kill the helper process → it is relaunched in seconds and a viewer with a resume ticket reconnects.
10. Windows Defender / your EDR: no detections for the signed build; behavioural rules for “process launched via CreateProcessAsUser by a service” may need an exclusion.

## Troubleshooting
| Symptom | Look at |
|---|---|
| Service won't start | Event Viewer → Application → “RemoteTool service failed to start”; `%ProgramData%\RemoteTool\service\logs\audit-service-*.jsonl` |
| Black picture at login screen | `helper_error`/`helper_started` events; helper must be SYSTEM in the console session (validate script check) |
| “Wrong password” though correct | master switch off, no password set, breaker tripped (`unattended_unavailable` in the log), or you used the one-time password |
| No banner | only on the user desktop; check helper is running in the user's session |
