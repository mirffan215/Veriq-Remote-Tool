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
Multiple relay addresses for failover: Phase 2.

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

## Dependencies (pinned in `Directory.Packages.props`)
SkiaSharp 2.88.9 (JPEG), System.IO.Hashing 8.0.0 (xxHash64 tile hashes), System.Security.Cryptography.ProtectedData 8.0.0 (DPAPI), test-only: xunit 2.9.2, Microsoft.NET.Test.Sdk 17.11.1,
xunit.runner.visualstudio 2.8.2, SkiaSharp.NativeAssets.Linux.NoDependencies 2.88.9. Framework: .NET 8, ASP.NET Core 8 (relay). No other runtime dependencies.

## Manual test checklist (two PCs, ideally on different networks)
1. Copy `RemoteTool.exe` to PC A and PC B (no installer). Start both: each shows its own 9-digit ID + password; **restart A → same ID**.
2. Configure the same relay on both → status "Relay: Online". Check the relay log shows the ID but no content.
3. On B enter A's ID + password → A shows the consent dialog (Deny is the default button) → Allow → B sees A's screen and can type/click smoothly (≥15 FPS on LAN).
4. A shows the red banner; click **Disconnect** → B's window reports the end. Reconnect (new password needed) and test **Ctrl+Alt+Shift+Q** on A.
5. Wrong password ×5 from B → B blocked, A's password changed, `source_blocked` in A's audit log.
6. Mode A: on A enable direct connections (port 21118), allow-list B's IP; B connects with `A-ip:21118`. Verify a non-listed IP is refused.
7. View-only checkbox on A → B can see but not control. Deny → B shows "denied".
8. Kill B's network mid-session → A's session ends within ~15 s, no stuck keys on A (hold a key on B while unplugging).
9. Multi-monitor host (viewer shows primary only in Phase 1), DPI 125 %/150 % on host **and** viewer: the mouse lands on the same pixel everywhere.
10. Inspect logs on both sides (`%ProgramData%\RemoteTool\logs\audit-host-*.jsonl`, `audit-viewer-*.jsonl`): connect, consent, session start/end with duration; no passwords or screen data.
11. Clean machine with no .NET installed: the exe starts. Windows 10 / Server 2019: expect the TLS 1.3 limitation (DECISIONS D-02).
