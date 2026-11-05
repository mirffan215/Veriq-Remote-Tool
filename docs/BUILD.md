# Build, deploy and verify

## Prerequisites
* .NET SDK 8.0.x. The WPF app needs the Windows Desktop workload (installed with the Windows SDK build). Everything else builds on Windows or Linux.
* PowerShell 7+ for the scripts.

## Build and test
```powershell
dotnet test RemoteTool.sln -c Release          # Windows: builds everything incl. WPF app
dotnet test tests/RemoteTool.Core.Tests        # protocol, TLS, handshake, MITM, fuzz, lockout, settings, audit
dotnet test tests/RemoteTool.Relay.Tests       # relay over real Kestrel TLS 1.3, opacity, duplicate ID, rate limits
dotnet test tests/RemoteTool.Capture.Tests     # tile diffing, JPEG round trip, coordinate mapping
```
On Linux/macOS the WPF project cannot be built; test the three projects above individually.

## Publish
```powershell
./scripts/publish-app.ps1                      # -> artifacts/app/RemoteTool.exe (+ .sha256)
./scripts/publish-app.ps1 -SignThumbprint <CERT_SHA1>   # also Authenticode-signs and timestamps
./scripts/publish-relay.ps1 -Runtime linux-x64 # -> artifacts/relay-linux-x64/RemoteTool.Relay
```
`publish-app.ps1` runs: vulnerability scan → tests → `dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
-p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true` → hash (and sign).
The exe needs no installer and no .NET runtime. Settings: `%AppData%\RemoteTool\settings.json`, logs `%ProgramData%\RemoteTool\logs`
(falls back to `%LocalAppData%`). **Portable mode:** create an empty file `portable.flag` next to the exe → everything goes to `data\` next to it.

## Relay deployment
Needs a small VPS/VM (1 vCPU / 512 MB is enough for hundreds of sessions; traffic is the limiter) with **one inbound port** (default 8443/TCP).
1. Firewall: allow only the relay port inbound (and SSH from your admin network). `/healthz` listens on loopback only.
2. Certificate: best is a real certificate (`Relay__CertificatePath`, `Relay__CertificatePassword`, e.g. Let's Encrypt PFX) — clients then validate via the system store and the
   fingerprint field can stay empty. Without one, the relay generates a self-signed cert in `Relay__DataDirectory`, prints its SHA-256 fingerprint at start, and you paste that into the
   clients' "Relay certificate fingerprint" setting (pinning).
3. **Always set an access key**: `Relay__AccessKey=<long random string>`; distribute to clients via `REMOTETOOL_RELAY_KEY` (Intune script) or the Settings tab.

Docker (from repo root):
```bash
docker build -f src/RemoteTool.Relay/Dockerfile -t remotetool-relay .
docker run -d --restart=always --name relay -p 8443:8443 -e Relay__AccessKey='…' -v relay-data:/app/data remotetool-relay
```
systemd (linux-x64 single file):
```ini
[Service]
ExecStart=/opt/remotetool-relay/RemoteTool.Relay
Environment=Relay__Port=8443 Relay__AccessKey=… Relay__DataDirectory=/var/lib/remotetool-relay
User=remotetool
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/remotetool-relay
Restart=always
```
Settings (`appsettings.json` or `Relay__*` env): `Port, HealthPort, AccessKey, CertificatePath/Password, DataDirectory, MaxConcurrentSessions (200), MaxRegisteredHosts, MaxConnections,
IdleTimeoutSeconds (90), ConnectsPerMinutePerIp (10), FailedLookupsPerMinutePerIp (5), RegistrationsPerMinutePerIp`. Logs go to stdout (metadata only).
Failover: give clients several relay addresses (`relay1.example.com:8443, relay2.example.com:8443`). Relays are independent and stateless, so run two on different hosts/providers; the same access key and (optionally) both fingerprints, comma-separated, go in the client settings.

## Clients: first-run configuration
Settings tab → *Relay server* `relay.example.com:8443`, *access key*, optional *fingerprint*. Or silently: set `REMOTETOOL_RELAY`, `REMOTETOOL_RELAY_KEY`, `REMOTETOOL_RELAY_FP`
before the first launch (applied only to empty settings).

## Code signing (Authenticode) and allow-listing
Unsigned remote-access tools are routinely quarantined. Before rollout:
1. Obtain a code-signing certificate from a public CA (OV/EV) or issue one from your internal PKI (then distribute the root to endpoints). Keep the key in an HSM / Azure Key Vault (never in the repo).
2. Sign: `scripts/publish-app.ps1 -SignThumbprint …` (SHA-256, RFC 3161 timestamp). Verify: `signtool verify /pa RemoteTool.exe`.
3. **Intune (Win32 app)**: wrap `RemoteTool.exe` with the Win32 Content Prep Tool; install command copies it to `%ProgramFiles%\RemoteTool\` (or per-user path) and creates a Start-menu shortcut; detection rule = file exists + version/hash.
4. **Defender / AppLocker / WDAC**: add a publisher (certificate) rule for your signing cert rather than a path or hash rule; submit the signed build to Microsoft Security Intelligence as a false-positive request if needed;
   with Defender for Endpoint add a *file/certificate indicator* "Allow" for the signer. Inform your SOC that the tool and the relay host are sanctioned.
5. Record the SHA-256 (`RemoteTool.exe.sha256`) of each release in your change log.

## Phase 3 tooling
```powershell
dotnet run -c Release --project tools/RemoteTool.Bench          # tile-JPEG numbers anywhere; + H.264 on Windows 11. BENCH_1080=1 for 1080p
RemoteTool.exe --bench-codec result.md                           # same, from the shipped exe
RemoteTool.exe --verify-audit "%ProgramData%\RemoteTool\service\logs" service     # hash-chain check (exit code 0 = intact)
RemoteTool.exe --export-recording file.rtrec C:\review [--machine]                   # decrypt a recording to PNGs / stream.h264
RemoteTool.exe --configure-service --relay r1:443 --relay-key-env RT_KEY --password-env RT_PW --enable   # elevated, headless
./scripts/sign-app.ps1 -File artifacts\app\RemoteTool.exe -Thumbprint <SHA1>
./scripts/package-intune.ps1 -IntuneWinAppUtil C:\tools\IntuneWinAppUtil.exe
./scripts/validate-windows.ps1                                    # on a disposable Windows 11 VM, elevated
```
Guides: `SERVICE.md` (architecture, controls, validation checklist), `INTUNE.md` (packaging, allow-listing, updates).

## Dependencies (pinned in `Directory.Packages.props`)
SkiaSharp 2.88.9 (JPEG/PNG), Vortice.MediaFoundation 3.8.3 (Media Foundation COM wrappers for H.264), System.ServiceProcess.ServiceController 8.0.1 (service shell), System.IO.Hashing 8.0.0 (xxHash64 tile hashes), System.Security.Cryptography.ProtectedData 8.0.0 (DPAPI), test-only: xunit 2.9.2, Microsoft.NET.Test.Sdk 17.11.1,
xunit.runner.visualstudio 2.8.2, SkiaSharp.NativeAssets.Linux.NoDependencies 2.88.9. Framework: .NET 8, ASP.NET Core 8 (relay). No other runtime dependencies.

## Manual test checklist (two PCs, ideally on different networks)
1. Copy `RemoteTool.exe` to PC A and PC B (no installer). Start both: each shows its own 12-digit code + password; **restart A → same ID**.
2. Configure the same relay on both → status "Relay: Online". Check the relay log shows the ID but no content.
3. On B enter A's ID + password → A shows the consent dialog (Deny is the default button) → Allow → B sees A's screen and can type/click smoothly (≥15 FPS on LAN).
4. A shows the red banner; click **Disconnect** → B's window reports the end. Reconnect (new password needed) and test **Ctrl+Alt+Shift+Q** on A.
5. Wrong password ×5 from B → B blocked, A's password changed, `source_blocked` in A's audit log.
6. Mode A: on A enable direct connections (port 21118), allow-list B's IP; B connects with `A-ip:21118`. Verify a non-listed IP is refused.
7. View-only checkbox on A → B can see but not control. Deny → B shows "denied".
8. Kill B's network mid-session → A's session ends within ~15 s, no stuck keys on A (hold a key on B while unplugging).
9. Multi-monitor host (viewer shows primary only in Phase 1), DPI 125 %/150 % on host **and** viewer: the mouse lands on the same pixel everywhere.
10. Inspect logs on both sides (`%ProgramData%\RemoteTool\logs\audit-host-*.jsonl`, `audit-viewer-*.jsonl`): connect, consent, session start/end with duration; no passwords or screen data.
11. Clean Windows 11 machine with no .NET installed: the exe starts.

### Phase 2 checks
12. **Clipboard:** copy text on B, paste on A, and vice versa (including multi-line and non-Latin text). Turn *Allow clipboard* off on A → nothing syncs. Logs show `clipboard_*` with sizes only.
13. **File transfer B→A:** viewer toolbar *Send file…* (try 1 KB, 100 MB, and an empty file) → A gets a confirmation (default *No*) → file appears in `Documents\RemoteTool Received`; compare `Get-FileHash` on both sides. Decline once → nothing saved.
    Try a file named with a long name / reserved name. **A→B:** banner *Send file…*. Kill the network mid-transfer: no `.part` file remains.
14. **Multi-monitor:** host with 2 monitors → viewer shows *Screen 1* button → switch; mouse clicks land correctly on the second monitor; test mixed DPI (100 % + 150 %).
15. **Reconnect:** during a session unplug B's network (or disable the adapter) for ~20 s, re-enable → B shows "reconnecting…", then the screen returns **without** a new password or consent dialog; A's audit log has `session_resumed`. Disconnect via the button, then confirm no automatic reconnect happens.
16. **Quality adaptation:** throttle B's link (Windows 11 *Network Link Conditioner* / `clumsy`) → picture gets softer, then slower, and recovers when the throttle is removed. Stats bar shows FPS/latency/KB/s.
17. **Address book:** save an ID with a nickname, restart the app, double-click the entry. No passwords appear in `settings.json`.
18. **Relay failover:** configure two relays; stop relay 1 → within ~1 min the host shows Online on relay 2 and a viewer still connects by ID. Stop the relay process with `SIGTERM`/`docker stop` → logs show a clean shutdown.

### Phase 3 checks (two PCs + one disposable Windows 11 VM)
19. **Arabic/RTL:** Settings → Language → العربية → Save → restart. Windows mirror; ID, password, addresses stay left-to-right. Switch back to English.
20. **Recording:** (service PC) enable *Record unattended sessions*; connect; the viewer shows “● REC”, the banner shows “● REC”; end the session; `--export-recording` produces PNGs; `--verify-audit` still passes. Flip a byte in the `.rtrec` → export fails.
21. **Audit chain:** edit one line of an audit log in Notepad → `--verify-audit` reports the line; restore → passes.
22. **H.264:** on both PCs leave *Use H.264* on, scroll a long document on the host; the viewer's status bar shows “· H.264” and KB/s is far lower than with the setting off on either side. Disable the Media Feature Pack on one PC or untick the setting → session still works with tiles.
23. **Unattended / service:** run `scripts\validate-windows.ps1`, then SERVICE.md “Validation checklist” items 2–10 from the second PC.
24. **Allow-listing:** deploy the signed package through Intune to a pilot group (INTUNE.md); confirm no Defender/SmartScreen block and the detection rule turns green.
