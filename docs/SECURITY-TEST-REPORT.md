# Security test report

Scope: the Core protocol/handshake, host and viewer sessions, relay, LAN discovery, file/clipboard handling, unattended service logic, logging and the
source tree. Date of this run: see the git history of this file. **Not in scope / not possible here:** anything that only runs on Windows (service launch, secure
desktop, SendSAS, DPAPI, WPF UI, Media Foundation) and an independent penetration test — see *What was NOT tested*.

Totals on this run (Linux, .NET 8): **Core 163 · Relay 23 · Capture 22 = 208 automated tests, 0 failing**; the Core suite was repeated many times to look for flakiness.

## How it was tested
| Method | Where | What it proves |
|---|---|---|
| **Attack tests** with a hand-rolled protocol client (`RawPeer`) over real TLS/TCP | `SecurityAttackTests`, `RelayAttackTests` | the system refuses what a hostile peer can actually send |
| **Fuzzing**: random frames before auth, 25 rounds × 40 random frames *inside* an authenticated session, parser fuzz (network, helper pipe, LAN discovery, JPEG) | `SecurityAttackTests`, `FramingTests`, `HelperProtocolTests`, `LanDiscoveryTests`, `HostileImageTests` | no crash, no wedged host, no unobserved background exceptions |
| **Static policy tests** on the source tree (banned APIs, TLS versions, certificate callbacks, process launches, constant-time compares, committed secrets) — mutation-checked (planted violations fail the test) | `SecurityPolicyTests` | regressions are caught on every build |
| **External probe** of a running relay with `openssl s_client` | manual, results below | what an outsider sees |
| **Dependency scan** `dotnet list package --vulnerable --include-transitive` per project | `scripts/check-vulnerabilities.ps1`, CI | no known-vulnerable packages (10/10 restorable projects clean) |
| Log/secret inspection of real log files and relay logs | `SecretsNeverReachTheAuditLogsOnDisk…`, `RelayLogsContainMetadata…` | passwords, resume tickets, relay key, names never logged |

## Results by threat
| Threat | Result | Evidence |
|---|---|---|
| TLS downgrade (1.2/1.1) to host and relay | **refused** | `TlsDowngradeToOlderVersionsIsRefused`, `RelayRefusesTlsOlderThan13`; openssl: TLS 1.2 → `protocol_version` alert, 1.1/1.0 impossible |
| Peer without certificate | **refused** | `ClientWithoutACertificateGetsNowhere` |
| Skipping authentication (consent/mouse/key/clipboard/file offer/auth-response as first message) | **dropped, nothing reached consent or input** | `SkippingTheHandshakeNeverReachesConsentOrInput` (6 variants) |
| Acting after a *denied* consent | **no input injected, no session** | `ConsentCannotBeSkippedByAuthenticatedButUnconsentedPeer` |
| Replay of a captured login proof (same nonce, same proof) | **rejected** | `CapturedProofCannotBeReplayedOnAnotherConnection` |
| Forged proof; reflection of the host-role proof | **rejected** | `ProofForOneRoleOrOneConnectionIsUselessForAnother` |
| Man-in-the-middle / TLS-terminating relay | **detected** | `ActiveManInTheMiddleIsDetected` |
| Rogue host or rogue LAN neighbour impersonating a PC | **viewer aborts** (cannot forge the host proof without the password) | `RogueHostWithoutThePasswordCannotImpersonateTheRealOne` |
| Brute force / distributed guessing | per-source lockout + rotation; unattended global breaker | `WrongPasswordFailsAndLocksOut…`, `DistributedGuessingTripsTheBreaker…` |
| Viewer sending host-only messages; random frames in a live session | **session ended, inputs released, host keeps serving** | `HostOnlyMessagesFromTheViewer…`, `AuthenticatedFuzzing…` |
| Hostile names (control chars / bidi) | **rejected on the wire / neutralised for display** | `HostileViewerNamesAreRejectedOrNeutralised` |
| Oversized frame before auth | **dropped without buffering** | `OversizedFramesBeforeAuthentication…` |
| **Unauthenticated connection flood** | **FINDING F1 — fixed** | `IdleConnectionsFromOneAttackerCannotLockOutOtherUsers…` |
| **Hostile image geometry against the viewer** | **FINDING F2 — fixed** | `HostileGeometryCannotMakeTheViewerAllocateGigabytes`, `JpegWhoseHeaderClaimsHugeDimensions…` |
| Relay: guessed pairing token; stolen token with wrong ID; ID hijack; registration flood; garbage / oversized / wrong-type first frame; session limit; cross-talk between sessions; secrets in relay logs | **all refused / isolated** | `RelayAttackTests` (12 tests) |
| LAN discovery: amplification, malformed/forged replies, rate limit, invisibility by default, reflection | **bounded** (reply ≤ probe, ≥128-byte probes only, 5 replies/10 s/source, silent unless made visible) | `LanDiscoveryTests` (13 tests) |
| File transfer: traversal, reserved names, ADS, bidi, corruption, out-of-order, unsolicited chunks, disconnect | **refused / cleaned up** | `FileNameSanitizerTests`, `FileTransferUnitTests` |
| Secrets in logs | **none found** (host, viewer, relay) | log tests above |
| Weak crypto / old TLS / unvetted trust callbacks / shell execution / predictable RNG / committed keys | **none in product code** | `SecurityPolicyTests` |
| Audit-log tampering | **detected** (edit, delete, insert) | `ChainVerifiesAcross…` |
| Recording tampering / reordering / gaps | **detected** | `RecordsEncryptedAndReadsBack…` |

## Findings during this test pass (all fixed, with regression tests)
* **F1 — Pre-auth slot exhaustion (availability, high).** The host allowed only 4 unauthenticated connections *in total*; four idle sockets from anyone locked every real user out for up to 15 s, repeatedly.
  *Fix:* 16 in total, **2 per source**, TLS-start timeout 8 s. Verified by the test that failed before the fix.
* **F2 — Viewer DoS through hostile geometry (availability, medium).** A malicious host could announce 65535×65535 surfaces/rectangles or a JPEG whose *header* lies about its size, making the viewer allocate gigabytes.
  *Fix:* `MaxFramePixels` (8192²) enforced in every message parser, rectangle-area budget (≤4× the frame), and `JpegCodec.DecodeExpecting` reads the header and refuses a size different from the announced rectangle *before* allocating.
* **F3 — The vulnerability scan could report "clean" when it had failed to run** (solution-level `dotnet list` errored on one SDK; the script only looked for the words "has the following vulnerable packages").
  *Fix:* per-project scan; a scan that cannot run, or prints something unrecognised, now fails the build.

## Residual risks (known, not fixed) — read these
1. **Password proof is not a PAKE (highest remaining risk).** An attacker who can *impersonate the host* — a malicious relay, **or a spoofed answer on the LAN** — receives one viewer proof and can try to guess the password offline.
   Cost: 31⁸ ≈ 8.5·10¹¹ candidates × 600 000 PBKDF2 rounds each. Not trivial to break, not impossible for a well-funded attacker with GPUs, **and the one-time password stays valid until used**.
   Mitigations today: PBKDF2 600k, channel binding (a MITM cannot *relay* the proof), the viewer checks the host proof (a rogue host cannot *log in*), "look on the local network first" is **off by default**.
   **Recommended next step:** replace the proof with a vetted augmented PAKE (OPAQUE or SPAKE2+). Until then, treat LAN discovery results as untrusted hints and prefer the relay path on untrusted networks.
2. **CPU cost of the proof**: each unauthenticated attempt makes the host run a 600k-round PBKDF2 (~100–200 ms). Bounded by 2/source and 16 total pre-auth connections, 5 failures/15 min lockout, but a distributed attacker can keep a host busy.
3. **LAN visibility discloses** the 12-digit code, the display name and the port to everyone on the subnet while enabled (off by default; firewall rules limited to Private/Domain + local subnet).
4. **Relay access key is a shared secret**; anyone holding it can register IDs and relay traffic (cannot read it). Rotate by redistributing.
5. **Viewer-side H.264 decode** runs the OS decoder on data from the host; sessions fall back to tiles on any error, but a decoder vulnerability would be a Windows vulnerability (keep Windows updated).
6. A **compromised endpoint** (host or viewer PC) is out of scope: whoever controls the OS controls the session.

## What was NOT tested
* All Windows-only behaviour: service/helper launch, pipe ACL, secure-desktop capture, SendSAS, DPAPI wrapping, firewall rules' effect, banner/hotkey, WPF UI, Media Foundation. See `docs/SERVICE.md` validation checklist and `scripts/validate-windows.ps1`.
* No independent penetration test, no TLS fuzzing of the OS stack, no side-channel/timing measurements beyond using `FixedTimeEquals`, no load testing of the relay at scale, no review of the relay host's operating system or network.

## Re-running
```powershell
dotnet test tests/RemoteTool.Core.Tests            # attack, fuzz, static-policy and unit tests
dotnet test tests/RemoteTool.Relay.Tests           # relay attack tests over real Kestrel TLS 1.3
dotnet test tests/RemoteTool.Capture.Tests         # hostile-image tests
./scripts/check-vulnerabilities.ps1                # dependency scan (fails if it cannot run)
openssl s_client -connect relay.example.com:8443 -tls1_2    # must fail;  -tls1_3 must succeed
```
