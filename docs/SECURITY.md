# Security model

Scope: RemoteTool.App (host+viewer) and RemoteTool.Relay. Aligned to ISO/IEC 27001:2022 (A.5.15 access control, A.8.5 secure authentication, A.8.15 logging,
A.8.24 cryptography, A.8.26 application security) and NCA ECC (identity/access, cryptography, logging, secure development) — mapping is indicative; your ISMS owner confirms applicability.

## Assets and trust
* Assets: control of an employee PC, the screen contents, keystrokes/clipboard/files in transit, relay access key, audit logs.
* The **relay is untrusted for confidentiality and integrity** (it is internet-facing and could be compromised). It is trusted only for availability and rate limiting.
* The **host user** is the final authority: every session needs an explicit Allow click (no unattended mode in Phase 1).

## Threats and controls

| Threat | Controls | Tests |
|---|---|---|
| **MITM on the network** | Inner TLS 1.3 only (no downgrade, checked post-handshake); mutual certificates; handshake proofs bound to both cert fingerprints | `ActiveManInTheMiddleIsDetected` |
| **Malicious / compromised relay** | End-to-end inner TLS; relay only splices bytes; channel binding makes a TLS-terminating relay fail authentication; relay sees only metadata (ID, IPs, byte counts); relay logs never contain payloads | `…RelayCarriesOnlyCiphertext`, MITM test |
| **Brute-force of the password** | 8×31-symbol one-time password; PBKDF2 600k; one attempt per connection; 5 failures per source ⇒ 15-minute block **and** password rotation; relay rate-limits connects (10/min/IP) and failed lookups (5/min/IP) | `WrongPasswordFailsAndLocksOut…`, `SlidingWindowLimits`, `FailedLookupsAreRateLimited…` |
| **ID enumeration** | 9-digit random IDs (never sequential, never derived from host data); one generic `NotFound` for unknown/offline/forbidden/throttled; per-IP limiter even for valid IDs once throttled | `UnknownAndOfflineIdsGetTheSameGenericAnswer` |
| **Replay** | Fresh 32-byte nonces from both sides in every proof; ephemeral per-connection TLS keys/certs; password single-use | `ProofsBindToFingerprintsAndRoles` |
| **Malformed/hostile frames** | 5-byte header validated before allocation; 4 KiB cap pre-auth, 16 MiB post-auth; unknown types rejected; strict parsers (truncation, trailing bytes, control chars, geometry); direction enforcement; per-rect/rect-count caps; JPEG decode errors terminate the session | `FuzzedStreams…`, `FuzzedPayloads…`, `FrameUpdateRejectsRectOutsideFrame` |
| **Session hijack / second viewer** | One active session (second ⇒ `Busy`); consent per session; password rotates on use | `SecondViewerIsRefused…` |
| **Unauthorized control** | Explicit consent dialog (Deny is default, 60 s timeout = deny); granted permissions = requested ∩ policy ∩ user's checkboxes; View-only mode; host drops input without Control permission | `ViewOnlyPolicyStripsControl…` |
| **Stolen/replayed resume ticket** | 192-bit random, single-use, 2-minute window after abnormal end only, killed by deliberate disconnect, still requires the channel-bound handshake, counts toward lockout | `SessionResumesAfterNetworkDrop…`, `ResumeTicketExpires…` |
| **Stuck keys/buttons** | Injector tracks pressed state and releases everything on disconnect/error/dispose; viewer releases on focus loss and close | `…ReleaseAllCalls` |
| **Hidden surveillance** | Always-on-top banner (re-asserted every 2 s) with Disconnect; emergency hotkey Ctrl+Alt+Shift+Q; audit log of every session | manual |
| **Inbound exposure** | Mode B is outbound-only (no listener). Mode A listener is **off by default**, user-enabled, optional IP allow-list | `AllowListRejectsOtherAddresses` |
| **Spoofed names in consent dialog** | Names validated (no control chars, ≤64 chars) and the connection source is shown separately (flagged as relay-reported) | `StringsRejectControlCharacters…` |
| **Secrets in logs/settings** | Audit writer refuses keys containing password/secret/key/token/screen/pixel/frame; relay access key DPAPI-protected; passwords never persisted; Connect tab clears the password field after use | `AuditLogWritesJsonLines…RefusesSecrets` |
| **Log tampering** | Local append-only files, rotation, retention; forward to SIEM (ship `%ProgramData%\RemoteTool\logs\*.jsonl` with your agent). Tamper-evidence/hash chaining: Phase 3 | – |
| **Path traversal / file abuse** | Names reduced to one sanitized component (no dirs, `..`, ADS `:`, reserved device names, bidi/format chars); fixed *RemoteTool Received* folder with containment check; per-transfer confirmation (default No); SHA-256 verified before the file appears; `.part` cleanup; 1 GiB cap; one transfer at a time; Mark-of-the-Web | `FileNameSanitizerTests`, `TraversalNameIsConfined…`, `CorruptedDataIsDetected…`, `OutOfOrderChunk…`, `DisconnectMidTransfer…`, `FileViewerToHost_…`, `FileHostToViewer_…` |
| **Clipboard abuse** | Text only; 1 MiB cap enforced by the parser; off unless the Clipboard permission was granted (policy ∩ user checkbox); echo suppression; audit records direction+size only | `TextSyncsBothWays…`, `ClipboardSyncsViewerToHost…AndIsOffWhenPolicyForbids` |
| **Local privilege abuse** | Runs `asInvoker` (no elevation, no service in Phase 1); input injection is limited to what the signed-in user can do (UIPI blocks elevated windows); no secrets in the repo | – |
| **Supply chain** | Pinned NuGet versions, vulnerability gate in scripts/CI, dependency list in BUILD.md, Authenticode signing guidance | CI |
| **Resource exhaustion** | Pre-auth connection cap (4), handshake/consent timeouts, heartbeat timeout, relay: max hosts/sessions/connections, idle timeout, pending-pairing timeout | partly tested |

## Phase 3 threats

| Threat | Controls | Verification |
|---|---|---|
| **Stolen/guessed permanent password** | ≥12 chars/3 classes; PBKDF2 600k; channel-bound proof; per-source lockout; **global breaker**; master switch; consent when a user is present; everything audited | automated: `DistributedGuessingTripsTheBreaker…`, `WrongOrDisabled…`, `PermanentPasswordTests` |
| **Local privilege escalation via the service** | exe runs from admin-only Program Files; service data ACL SYSTEM/Admins; helper pipe random name + SYSTEM-only ACL + client-PID check; helper protocol parsers are bounds-checked and fuzzed; no secrets on command lines | automated: protocol fuzz; **Windows validation: ACL checks** (validate script + SERVICE.md #7,#8) |
| **Silent surveillance** | banner + hotkey on the user desktop, consent when a user is present, audit; recording announced to host user and viewer | automated: consent/recording flags; Windows validation: banner/hotkey |
| **Recording abuse / leak** | off by default; screen-only (no keystrokes/clipboard/files); AES-GCM per-file key wrapped by DPAPI; tamper/gap detection; retention; hash audited | automated: `RecordsEncryptedAndReadsBack…`, retention test |
| **Audit tampering** | hash chain across rotation/restart, verifier tool | automated: `ChainVerifiesAcross…` (edit, delete, insert detected) |
| **Hostile H.264 stream from a malicious host** | decoder is the OS decoder MFT (patched via Windows Update); any decode error ⇒ fallback to tiles; frame/rect size caps unchanged | Windows validation |
| **Encoder/decoder crash taking the session down** | automatic codec fallback in both directions | automated: `H264IsNegotiated_FallsBack…`, `ViewerDecoderFailure…` |
| **Distributed denial of unattended access** | breaker pauses logins (documented trade-off D-29) | automated |

## Known limitations / residual risks (Phase 1)
1. **Windows 11 / Server 2022 only** (TLS 1.3; DECISIONS D-02/D-16).
2. **Password proof is not a PAKE** (D-04): a TLS-terminating malicious relay can attempt an offline guess of one 39.6-bit password through 600k PBKDF2 rounds.
3. Windows screen capture of the **secure desktop (UAC prompt, lock screen, Ctrl+Alt+Del)** is not possible from a user-session process; the viewer sees a frozen/black screen until Phase 3.
4. Input to **elevated windows** is blocked by UIPI until Phase 3.
5. Unsigned binaries will trigger SmartScreen/Defender heuristics; sign and allow-list (BUILD.md).
6. The relay access key is a shared secret; rotating it means redistributing it to clients. Treat the relay like any internet-facing service (patching, firewall, monitoring).
7. The WPF client was not compiled/run in the authoring sandbox (D-15, D-24); the first Windows build is part of acceptance.
8. A file or clipboard text from the viewer is data from a remote person: the user's confirmation is the control. Mark-of-the-Web makes SmartScreen warn on execution, but it is not malware scanning — keep Defender real-time protection on.
9. A viewer whose connection drops keeps a 2-minute resume window; anyone who steals the token *and* can complete the TLS handshake with it could resume. The token only ever travels inside the end-to-end channel.

## Phase 1 security checklist
- [x] TLS 1.3 only, mutual, ephemeral certs · [x] channel-bound password proof · [x] lockout + rotation · [x] consent before any control
- [x] banner + emergency hotkey (code complete, unverified on Windows) · [x] audit log (JSONL, rotation) · [x] frame fuzzing · [x] relay opacity test
- [x] Clipboard/file controls (Phase 2) · [x] resume tickets · [ ] service/UAC/login screen (Phase 3) · [ ] log hash-chain, session recording opt-in (Phase 3) · [ ] penetration test of the relay before internet exposure

## Final Phase 3 security checklist

Legend: **T** implemented and covered by automated tests that run on Linux CI · **W** implemented, needs the Windows validation (not executed by the author) · **O** operational task for you · **—** not done.

| Control | Status |
|---|---|
| TLS 1.3 only, mutual, ephemeral certs; channel-bound password proofs; MITM/relay-MITM detection | **T** |
| One-time password: single-use, rotation, lockout 5/15 min | **T** |
| Resume tickets: single-use, 2-minute window, killed by deliberate disconnect | **T** |
| Frame/parser hardening + fuzzing (network and helper protocol) | **T** |
| Consent default-deny, per-transfer file consent, path-traversal-safe names, hash-verified transfers | **T** |
| Clipboard text-only/size-capped/permission-gated | **T** |
| Permanent password: policy, storage as derived key, master switch, breaker, no one-time password in service mode | **T** |
| Unattended policy (auto-allow at login screen, ask when user present, control-only) | **T** (decision logic) · **W** (desktop detection on real Winlogon) |
| Service/helper launch (SYSTEM token, session id, pipe ACL, PID check), SendSAS, desktop switching, secure-desktop capture/input | **W** |
| Installer ACLs (Program Files, ProgramData), `sc` configuration, recovery actions | **T** (exact commands) · **W** (effect) |
| Banner + emergency hotkey; consent dialog; recording indicator | **W** |
| Session recording: encryption, tamper detection, retention, export | **T** (file format) · **W** (DPAPI wrapping) |
| Audit log hash chain + verifier | **T** |
| H.264 negotiation + fallback logic | **T** · MF encode/decode **W** |
| Arabic/RTL resources complete, placeholder parity | **T** · native-speaker review **O** |
| Code signing, Defender/AppLocker/WDAC allow-listing, Intune packaging | scripts and guides provided; certificates and policy **O** |
| SIEM forwarding of audit logs (incl. latest chain hash) and alert on `unattended_breaker_tripped`/`source_blocked` | **O** |
| Penetration test of the relay and the service before internet exposure | **O** |
| WGC/DXGI capture, hot-plug monitor changes, TPM-bound keys, OPAQUE/SPAKE2+ password proof, relay HA state | **—** (documented future work) |
