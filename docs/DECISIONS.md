# Design decisions

Format: ID — decision — reason / alternatives. Newest at the bottom of each phase.

## Phase 1

**D-01 Standalone project.** RemoteTool lives in its own folder/repo. It is unrelated to the VPMS or Facility-Management repositories
that happen to be mounted next to it in the build sandbox; none of their files or branch rules were touched.

**D-02 TLS 1.3 only ⇒ minimum OS is Windows 11 / Server 2022 (CONFIRMED by owner for Phase 2: Windows 11 only).**
The brief asks for TLS 1.3 only *and* Windows 10 / Server 2019+. Microsoft's SChannel does not implement TLS 1.3 on Windows 10 or
Server 2019 (it arrived with Windows 11 / Server 2022), and .NET's `SslStream` uses SChannel on Windows. Per rule "never weaken a
security requirement", the code **refuses anything below TLS 1.3** (`SslProtocols.Tls13`, verified after the handshake). Consequence:
the exe runs on Windows 11, Server 2022+ and Linux for the relay; on Windows 10 / Server 2019 the secure channel cannot be established.
Options, in order of preference: (1) fleet is Win 11 / 2022 ⇒ nothing to do; (2) Phase 3: add a managed TLS 1.3 transport
(BouncyCastle `Org.BouncyCastle.Tls`) behind the existing `TlsChannel` seam so Win 10 works without SChannel; (3) you explicitly accept
TLS 1.2 with ECDHE+AEAD only for those hosts (not done). *Please verify on your fleet before roll-out.*

**D-03 Mutual TLS with throw-away self-signed certificates.** ECDSA P-256 cert generated *per connection*; trust comes from the
channel-bound password proof (D-04), not from a CA. Certificates are round-tripped through PFX because SChannel cannot use in-memory
self-signed keys; the Windows key container is deleted on dispose.

**D-04 Password authentication = channel-bound HMAC proof over a PBKDF2-derived key, not a full PAKE.** No custom primitives: PBKDF2,
HMAC-SHA256, TLS only. Properties: password never on the wire; bound to both certificate fingerprints (defeats relay/MITM relaying);
mutual (host proves knowledge too); replay-proof (fresh nonces both sides); 1 attempt per connection, 5 failures/source ⇒ 15 min block + password rotation.
*Residual risk:* a **malicious relay that actively terminates TLS** gets one proof it can try to brute-force offline (≈39.6-bit password × 600k PBKDF2 iterations
≈ 5·10¹⁷ HMAC compressions ⇒ infeasible for realistic attackers, but not information-theoretically safe like a PAKE).
Upgrade path when a vetted .NET OPAQUE/SPAKE2+ library is chosen: bump `ProtocolConstants.Version`.

**D-05 Relay = ASP.NET Core Kestrel raw-TCP `ConnectionHandler` + TLS 1.3, engine is transport-agnostic.** `RelayEngine` works on `Stream`s so it is
unit/integration-testable; Kestrel adds limits (`MaxConcurrentConnections`) and a loopback `/healthz`. Outer TLS cert: provided PFX (e.g. Let's Encrypt) or an
auto-generated self-signed one whose SHA-256 fingerprint is logged at start and pinned in clients (`Relay certificate fingerprint` setting).
The relay never sees plaintext: inner TLS runs through it (proven by `ViewerReachesHostByIdThroughRelay…` which inspects every forwarded byte).

**D-06 Duplicate ID handling.** Hosts send a random per-process `instanceId`. Same instance reconnecting replaces its stale entry; a different live
instance with the same ID gets `IdTaken`. The host retries 3× (10 s apart – covers a stale entry left by its own crashed process) and then regenerates and persists a new ID.
The relay keeps IDs in memory only.

**D-07 Brute-force keying.** Direct mode: source IP. Relay mode: the host only sees the relay, so the key is the viewer address *claimed by the relay*
(trusted for lockout only, never for authorization) — and the relay itself rate-limits per IP (10 connects/min, 5 failed lookups/min ⇒ generic NotFound).

**D-08 GDI BitBlt capture first; DXGI/Windows.Graphics.Capture deferred to Phase 3.** The brief names WGC/DXGI as primary, GDI as fallback. I cannot run or
test Windows capture APIs in the build sandbox, so Phase 1 ships the documented fallback (works everywhere, no GPU dependency, ~15–30 FPS at typical office resolutions
with tile diffing). The `IScreenGrabber` seam is in place for a DXGI implementation.

**D-09 Keyboard = host-side scan-code translation.** Viewer sends virtual-key + extended flag; host maps VK→scan code with *its* layout and injects with `KEYEVENTF_SCANCODE`.
Local OS shortcuts (Win key, Alt+Tab, Ctrl+Alt+Del) are not captured by the viewer in Phase 1 (needs low-level hook; Ctrl+Alt+Del needs the Phase 3 service).

**D-10 Single-use password.** Rotated after every successful authentication and after every lockout. The user can also refresh it. A permanent password (DPAPI) and unattended access are
Phase 3 and opt-in. The IP allow-list (Mode A) is implemented now.

**D-11 Session ends when the main window is closed (no tray icon yet).** Keeps "is the host reachable?" visible to the user; tray + autostart come with the Phase 3 service.

**D-12 Secrets at rest.** Relay access key is stored DPAPI-protected (CurrentUser) in `settings.json`; passwords are never stored. Deployment defaults may be injected via
`REMOTETOOL_RELAY`, `REMOTETOOL_RELAY_KEY`, `REMOTETOOL_RELAY_FP` environment variables (preferred over command-line flags, which are visible in process lists).

**D-13 NuGet pinning** via `Directory.Packages.props` (central package management); `dotnet list package --vulnerable --include-transitive` gates the publish scripts and CI.

**D-14 i18n structure.** All UI text is in `Resources/Strings.resx` accessed through `Loc`/`{loc:T}`; `FlowDirection` follows the UI culture. Arabic satellite resources are Phase 3.

**D-15 Build/verification limits of the authoring sandbox.** Core, Relay, Capture, Input are built and tested on Linux. The WPF project (`RemoteTool.App`) could **not** be compiled there
(the sandbox SDK has no Windows Desktop workload and its network policy blocks the official SDK download). It is therefore *unverified by a compiler*; `.github/workflows/ci.yml` builds it on `windows-latest`.
First action on a Windows machine: `scripts/publish-app.ps1` and fix any compile errors.

## Phase 2

**D-16 Windows 11 only.** Owner confirmed (D-02): no managed-TLS fallback will be built. Windows 10 / Server 2019 are unsupported.

**D-17 Session resume instead of "re-enter password".** Passwords are single-use (D-10), so a reconnect needs a different credential. The host issues a 192-bit random, single-use *resume ticket* inside the
encrypted consent reply; it survives only abnormal ends, for 2 minutes. Resuming reuses the same channel-bound proof (D-04) with the ticket as secret, so there is no new weaker path. No consent dialog on resume
because the same authenticated viewer/host pair already consented; permissions can only shrink (policy re-applied). A viewer that has the ticket *is* the previously consented viewer; a stolen ticket is useless without
also being able to complete the channel-bound handshake within 2 minutes, and it dies on first use or on a deliberate disconnect.

**D-18 Transfers are receiver-controlled and hash-first.** Sender hashes before offering so the receiver can verify before the file becomes visible. Every incoming file needs a per-transfer confirmation (default No),
1 GiB cap (`MaxFileTransferMb` in settings.json), sanitized names (traversal, ADS, reserved device names, bidi/format characters, length), `.part` + atomic rename, Mark-of-the-Web, cleanup on disconnect.
Offers are processed off the read loop; otherwise a user pondering the dialog would stop heartbeats and the peer would time out.
Received files go to `Documents\RemoteTool Received` (portable mode: `data\RemoteTool Received`).

**D-19 Clipboard = plain text only, 1 MiB cap, echo-suppressed, permission-gated.** Files go through the file-transfer path (the brief's "files via file transfer"). Content is never logged; only direction and size.
Both host policy *and* the host user's consent checkbox can switch it off.

**D-20 Adaptive quality.** `AdaptiveQuality` reacts to how long the socket takes to accept a frame: quality 85→40 first, then frame rate 25→5 FPS; recovery in reverse. Pure logic, unit-tested; real-link tuning is Phase 3.

**D-21 Multi-monitor.** Viewer sends `MonitorSelect`; host switches the capture source, forces a keyframe and re-announces `ScreenInfo`; mouse mapping uses the active monitor. Hot-plug changes mid-session are not handled yet (reconnect).

**D-22 Relay failover is client-side.** Relays are independent (no shared state, by design: IDs live only in memory). A host registers on the first reachable relay and fails over on connect failures; viewers try every
configured relay until one pairs them (a "not found" from one relay is not final). Clients accept several comma-separated addresses and several pinned fingerprints. Graceful shutdown: relay drops registrations on stop and Kestrel drains for 20 s.

**D-23 Address book** stores target + nickname only (never passwords). Recent connections remain separate.

**D-24 WPF additions remain compiler-unverified** (see D-15). XAML well-formedness, resource keys and event-handler names are checked by script; the C# is syntax-checked.

## Phase 3

**D-25 Unattended access = separate Windows service + per-session SYSTEM helper (SERVICE.md).** The brief suggests `WTSQueryUserToken` + `CreateProcessAsUser`. That gives a *user* token, which (a) does not exist at
the login screen and (b) cannot open the secure Winlogon desktop (UAC, lock, login). The helper therefore runs with a duplicate of the service's SYSTEM token whose `TokenSessionId` is set to the console session
(needs SeTcb, held by LocalSystem). `WTSQuerySessionInformation` is used only to name the signed-in user in the audit log. Capture and input live on **one dedicated thread** that calls `SetThreadDesktop(OpenInputDesktop)` before each operation
(desktop attachment is per thread). The service itself, not the helper, calls `SendSAS` (only services may).

**D-26 Everything Windows-only in Phase 3 is unexecuted.** Service shell, WTS launch, pipe ACL, desktop switching, SendSAS, Media Foundation encode/decode, DPAPI, hotkey, banner, WPF — compiled (service/video projects on Linux with
platform attributes; WPF only syntax-checked) but **never run** by the author. Mitigations: all decision logic sits behind interfaces and is tested with a simulated helper (`ServiceRuntimeTests`: 8 end-to-end scenarios incl. helper crash + resume);
`scripts/validate-windows.ps1` and the SERVICE.md checklist define the on-Windows acceptance; a Windows CI job builds the app and runs the codec benchmark. **Phase 3 acceptance (UAC, lock/login screen, H.264 bandwidth) is therefore NOT yet demonstrated.**

**D-27 Permanent password storage.** Only `PBKDF2(password, salt, 600k)` + salt are stored (machine-DPAPI protected, ACL’d file); the plaintext never touches disk. The derived key is password-equivalent for authentication, so the ACL is a real control.
Policy: ≥12 chars, ≥3 classes. A stolen *file* can be used to impersonate the password only on the same machine's DPAPI scope. Trade-off vs. a verifier-only scheme: the existing handshake needs the HMAC key on the host; moving to OPAQUE/SPAKE2+ (D-04) would remove it.

**D-28 Unattended ≠ unobserved.** Default `ConsentWhenUserPresent=true`: if anybody is working at the desktop they are asked, and only the login/lock screen is auto-allowed. The master switch is separate from the password so a leaked
password alone does nothing on a PC where the switch is off. Service mode accepts no one-time password at all, and clipboard/file transfer are never available unattended.

**D-29 Brute-force defence for an always-valid password.** Per-source lockout (D-07) is insufficient behind a relay that can be fed varied source addresses, so a global breaker (20 failures/15 min ⇒ unattended paused 15 min) was added.
Cost: an attacker can deny unattended access for 15 min at a time (availability for confidentiality); the relay's per-IP limits and the SOC alert on `unattended_breaker_tripped` are the counter.

**D-30 H.264 via Media Foundation, with three-level fallback.** Hardware MFT (async event model) → Microsoft software MFT (sync) → tiles; failure at any moment (init, encode timeout, decoder error) switches that session to tiles via `CodecSwitch` without
dropping it. `ICodecAPI` (keyframe on demand, CBR, low latency, no B-frames) is bound through a small `ComImport`; Vortice.MediaFoundation 3.8.3 supplies the MF wrappers. Frames are only encoded when the picture changed.
**Not measured:** the brief's “H.264 measurably reduces bandwidth” needs a Windows 11 run: `RemoteTool.Bench` / `RemoteTool.exe --bench-codec` / the `codec-benchmark-windows` CI job produce the table. Expectation (not a result): large for scrolling/video, small for typing/idle.

**D-31 Recording is host-side, encrypted, screen-only.** Keystrokes are deliberately *not* recorded (they would capture passwords). AES-256-GCM with a per-file key wrapped by DPAPI; counters in nonce+AAD detect tampering and gaps; the consent dialog and the viewer UI announce recording;
retention default 30 days; the file hash is audited. Anyone who can use the same DPAPI scope can decrypt — that, plus ACLs, is the access control.

**D-32 Audit log is a hash chain.** Each line carries `prev` = SHA-256 of the previous line, across rotation and restarts; `AuditVerifier`/`--verify-audit` detect edits, deletions and insertions. Truncation of the newest lines is *not* detectable locally —
forward logs (or just the latest `prev`) to the SIEM for that. Older unchained logs are tolerated as a legacy prefix.

**D-33 Arabic/RTL.** Full `Strings.ar.resx` (110 keys, placeholder parity enforced by a test), RTL `FlowDirection` from the UI culture, IDs/passwords/addresses forced LTR. The translation was written without a native reviewer — **have an Arabic speaker review it**
(especially security wording). The UI shows no calendar dates (logs are ISO-8601 UTC), so Hijri display was not needed in this phase.

**D-34 Performance tuning, measured** (`tools/RemoteTool.Bench`, 1280×720 synthetic desktop content, 4 cores, steady state, ms per frame; bytes unchanged):
| Scenario | before | after |
|---|---:|---:|
| Idle | 1.1 | 1.1 |
| Typing | 1.3 | 1.5 |
| Window drag | 3.7 | 1.6 |
| Scrolling text | 15.0 | 8.3 |
| Video-like motion | 13.7 | 7.1 |
Changes: encode JPEG rects in parallel straight from the capture buffer (no copy), smaller full-frame bands (128 rows) so they parallelise, parallel tile hashing only above ~1.5 MP (below that threading cost more than it saved — found by measurement).
Bandwidth for scrolling is ≈43 Mbit/s at 720p/15 fps with tiles — this is the case H.264 is meant to fix.

**D-35 Windows 11 only (owner decision) and one exe.** Service, helper, setup, CLI tools and UI are modes of the single portable exe; the service copy is installed to Program Files. Closing the main window still exits the user-mode app (no tray yet).

## Requirements pass (internet code, LAN mode, security testing)

**D-36 Connection code = 12 digits (10–12 accepted).** The brief asked for 10–12 digits. New codes are 12 digits (≈9·10¹¹ values, uniform, no leading zero); 10–11 digit codes are still accepted. Older 9-digit IDs in existing settings are invalid now and are replaced automatically on start.
Combined with the relay's lookup limits (10 connects/min and 5 failed lookups/min per IP, identical "not found" answer), guessing a live code is impractical.

**D-37 LAN mode.** Direct connections already existed (IP:port). Added: (a) **discovery** — a 128-byte UDP probe to port 21119, answered only by PCs whose owner enabled *Visible on the local network*; reply ≤ probe size (no amplification), 5 replies/10 s/source;
(b) **connect by code on the LAN** — optional "look on the local network first", and automatic when no relay is configured; (c) the service's *Local network mode* also opens the firewall, **only** for this program, Private/Domain profiles and the local subnet.
Discovery output is an unauthenticated hint; authentication and consent are unchanged (tested). Off by default everywhere.

**D-38 Why LAN-first is opt-in.** With the current non-PAKE proof (D-04), a spoofed LAN answer can lure a viewer into sending one proof to an attacker. Doing that by default would be a downgrade compared with the relay path, so the user chooses it, and the report lists a PAKE as the top next hardening step.

**D-39 Findings from the security pass** (SECURITY-TEST-REPORT.md): per-source pre-auth limits (F1), geometry/JPEG-header caps (F2), vulnerability scan that cannot silently pass (F3).

## AnyDesk-style simplification (click-only access, access password, zero-config)
User feedback: the tool asked for too many settings. Decisions:
* **Main screen** = "Your Address" + remote-address box + Connect. Everything else is in Settings (Advanced is collapsed). Relay details are baked in at build time (BUILD.md).
* **Default connection = ask and Accept.** Wire protocol v4 adds a password-less *Consent* mode. Trade-off: with no shared secret, a malicious relay could MITM. Mitigation: a 6-digit
  security code derived from the nonces and both TLS certificate fingerprints, shown on both screens (host's Accept dialog tells the user to compare it); commit-then-reveal nonce prevents grinding;
  repeated denials lock the source out. Residual risk: it depends on a human comparing the code (as in Signal/ZRTP). A PAKE (SPAKE2+/OPAQUE) remains the recommended future hardening.
* **Access password** (optional, Settings): lets a viewer who knows it connect with no click (AnyDesk "unattended access"). Stored as derived key + salt (DPAPI), ≥12 chars, global failure breaker and per-source lockout; banner and Disconnect remain; control + clipboard only, never file transfer.
* The Windows service refuses click-only mode (nobody to click on the login screen): it always needs its permanent password.

## D-40 Windows 10 / Server 2019 support: TLS 1.2 (AEAD, forward-secret) fallback - supersedes D-02 and D-16
Owner request: the tool must work on Windows 10 and newer without checking builds. SChannel has no TLS 1.3 before Windows 11 / Server 2022, so a TLS-1.3-only rule excluded Windows 10 entirely.
Decision: all links (viewer-host, client-relay, relay listener) go through `TlsPolicy`: TLS 1.3 preferred; TLS 1.2 accepted **only** with ECDHE + AES-GCM / ChaCha20-Poly1305 (checked after the handshake on every OS,
and offered exclusively on non-Windows where the OS allows it). TLS 1.1 and older, CBC suites and RSA key exchange are refused (tests: `TlsDowngradeToOlderVersionsIsRefused`, `Tls12WithAForwardSecretAeadSuiteWorks_ButWeakSuitesAreRefused`, `RelayRefusesTlsOlderThan12`).
Why this is acceptable: peer identity never rests on TLS alone - the password/consent proofs are HMACs bound to both certificate fingerprints, so a MITM or a forced downgrade cannot authenticate; mutual certificates are still required.
What is lost: a downgrade attacker can push a Windows 11 pair from 1.3 to 1.2 (still forward-secret AEAD). No renegotiation or session tickets are used. A managed TLS stack (BouncyCastle) would give 1.3 everywhere but adds a large unaudited dependency; revisit if required.
Minimum OS: Windows 10 1809 / Server 2019 (build 17763; MSI launch condition).

## D-41 LAN scan and one-click firewall rules (owner request)
* **Scan** (`NetworkScanner`): TCP connect check only, user-initiated, never public address space (resolved names must also be private), max 4096 targets (/20), 128 parallel / 700 ms timeouts, no payload sent. It is a convenience list, not trust: connecting still goes through the full handshake and Accept/password. Each scan writes a `lan_scan` audit event (counts only).
* **Firewall**: elevated relaunch (`--firewall add|remove`) using the same `FirewallCommands` as the service: program-scoped, Private+Domain, `localsubnet`; `--wide` widens only to the three private blocks. Never Public profile, never "any". The UI never runs elevated (UAC prompt per action).
* Found while testing: a dead service-helper pipe made `ReleaseAll()` throw `ObjectDisposedException` out of the session cleanup; it is now contained so audit/recording/slot release always run.
