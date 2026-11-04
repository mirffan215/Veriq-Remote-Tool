# Design decisions

Format: ID — decision — reason / alternatives. Newest at the bottom of each phase.

## Phase 1

**D-01 Standalone project.** RemoteTool lives in its own folder/repo. It is unrelated to the VPMS or Facility-Management repositories
that happen to be mounted next to it in the build sandbox; none of their files or branch rules were touched.

**D-02 TLS 1.3 only ⇒ minimum OS is Windows 11 / Server 2022 (OPEN ISSUE, needs your call).**
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
