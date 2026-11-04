# RemoteTool wire protocol (version 3)

v3 (Phase 3) replaces `Hello.resume` with an auth *mode* byte (adds the permanent/unattended password), adds a codec set to `ConsentRequest`, the chosen codec + a recording flag to `ConsentResult`, and message types 20–22 (`SpecialKey`, `VideoFrame`, `CodecSwitch`). Older peers are refused (`VersionMismatch`).

v2 (Phase 2) adds `Hello.resume`, `ConsentResult.resumeToken`, `MonitorSelect`, and the clipboard / file messages. v1 and v2 peers refuse each other (`VersionMismatch`).

Keep in sync with `src/RemoteTool.Core/Protocol`. All integers are big-endian.

## 1. Layers

```
viewer ── TCP ── [Mode A: direct]  ────────────────────────── host
viewer ── TCP+TLS1.3 ── relay ── TCP+TLS1.3 ── host            [Mode B: outer links, relay-terminated]
viewer ══ TLS 1.3 (mutual, ephemeral certs) ═══ end-to-end ═══ host     inner channel, same in A and B
          └─ frames ─ Hello … AuthResult … Consent … ScreenInfo / FrameUpdate / input …
```

* **Inner channel** (always): TLS 1.3 only, both sides present a fresh self-signed ECDSA P-256 certificate
  (generated per connection). Certificate chains are *not* trusted; identity comes from §4 which is bound to the
  SHA-256 fingerprints of both certificates. The host is the TLS server, the viewer the TLS client.
* **Outer relay link** (Mode B only): TLS 1.3 to the relay, validated by pinned SHA-256 fingerprint or a public CA.
  It protects the ID and relay access key. The relay copies the inner channel's bytes and cannot read or alter them undetected.

## 2. Framing

```
[uint32 payloadLength][byte type][payload]
```
* `payloadLength` excludes the 5-byte header. Max 16 MiB (`MaxFramePayload`); **4096 bytes until authentication
  completes** (`PreAuthMaxFramePayload`); relay control frames max 512 bytes.
* Unknown `type` ⇒ connection closed. Reader never reads past the current frame. Allocation happens only after the length check.
* Strings: `uint16 byteLength` + UTF-8 (strict, control characters rejected). Byte arrays: `uint32 length` + bytes with a per-field cap.
* Every parser rejects truncated payloads *and* trailing bytes.

## 3. Message types

| Type | Name | Direction | Payload |
|---|---|---|---|
| 1 | Hello | V→H | `u16 version`, `str viewerName(≤64)`, `32B nonceV`, `u8 authMode` (0 one-time password, 1 resume ticket, 2 permanent password) |
| 2 | AuthChallenge | H→V | `str hostName`, `32B nonceH`, `16B salt` |
| 3 | AuthResponse | V→H | `32B viewerProof` |
| 4 | AuthResult | H→V | `bool ok`, `u8 failure`, `32B hostProof` (zeros on failure) |
| 5 | ConsentRequest | V→H | `u8 requestedPermissions`, `u8 codecs` (bit0 tiles — mandatory, bit1 H.264) |
| 6 | ConsentResult | H→V | `bool granted`, `u8 grantedPermissions`, `u8 denyReason`, `bytes resumeToken(≤64, ASCII hex; empty if denied)`, `u8 codec` (1 tiles, 2 H.264), `bool recording` |
| 7 | ScreenInfo | H→V | `u8 n`, `u8 activeMonitor`, n × (`u8 idx, i32 x,y,w,h, bool primary, str name`) |
| 8 | FrameUpdate | H→V | `u8 monitor, u32 seq, u16 w, u16 h, bool keyframe, u16 nRects`, nRects × (`u16 x,y,w,h`, `bytes jpeg`) |
| 9 | CursorUpdate | H→V | `u8 shape` |
| 10 | MouseEvent | V→H | `u8 kind(move/down/up/wheel/hwheel), u8 button, u16 x, u16 y (0..65535 of monitor), i32 wheelDelta` |
| 11 | KeyEvent | V→H | `u16 virtualKey(1..254), u8 flags(1=up, 2=extended)` |
| 12 | ClipboardData | both | `u8 format(0 = UTF-8 text)`, `bytes text(≤1 MiB)`; newlines allowed, strict UTF-8 |
| 13 | FileOffer | sender→receiver | `u32 id`, `str name(≤255)`, `u64 size`, `32B sha256` |
| 14 | FileChunk | sender→receiver | `u32 id`, `u64 offset`, `bytes data(≤256 KiB, 64 KiB used)` |
| 15 | FileAck | receiver→sender (and sender→receiver for Cancel) | `u32 id`, `u8 status(0 accept,1 reject,2 complete,3 hash mismatch,4 error,5 cancel)`, `u64 received` |
| 16 | Ping | both | `u64 senderTickMs` |
| 17 | Pong | both | echo of the Ping payload (RTT) |
| 18 | Bye | both | `u8 reason`, `str text(≤128)` |
| 20 | SpecialKey | V→H | `u8 kind` (0 = Ctrl+Alt+Del). Honoured only when the host runs as the service (`SendSAS`) and Control was granted; otherwise audited and ignored |
| 21 | VideoFrame | H→V | `u8 monitor, u32 seq, u16 w, u16 h, bool keyframe, bytes annexB` — one H.264 access unit; keyframes carry SPS/PPS |
| 22 | CodecSwitch | both | `u8 codec`: host→viewer “stream is now tiles” after an encoder failure; viewer→host “my decoder failed, send tiles”. The next frame is a keyframe |
| 19 | MonitorSelect | V→H | `u8 monitorIndex`; host replies with a new `ScreenInfo` and a keyframe of that monitor |

Permissions bits: 1 Control, 2 Clipboard, 4 FileTransfer. Message direction is enforced: e.g. a viewer sending `FrameUpdate` is a protocol error.
Frame rects must lie inside `w×h`; ≤4096 rects; ≤8 MiB per JPEG.

### File transfer
`FileOffer` (hash known up-front) → receiver asks its user (60 s, default *No*) → `FileAck(accept|reject|error)` → sequential `FileChunk`s (offset must equal bytes received) → receiver verifies SHA-256 →
`FileAck(complete | hashMismatch)`. Receiver writes `<name>.part` in the *RemoteTool Received* folder and renames only after verification; the name is sanitized to a single component and the file gets a
`Zone.Identifier` (ZoneId=3). One incoming and one outgoing transfer at a time; default cap 1 GiB; a disconnect deletes the partial file. The offer is handled off the read loop so heartbeats keep flowing while the user decides.

### Resume after a network drop
After consent the host returns a random 192-bit `resumeToken` (valid for the live session). If the session ends *abnormally* (timeout / protocol error) the token stays valid for 2 minutes; a normal
disconnect, a host-initiated disconnect or a lockout invalidates it. To resume, the viewer opens a new connection and sends `Hello.resume = true`; §4 runs with the token as the shared secret instead of the one-time
password. On success the host skips the consent dialog (permissions = previous grant ∩ current policy), retires any half-dead old session, and returns a **new** token. The token is single-use, comparisons are constant-time,
failures count toward the same lockout.

Heartbeat: both sides send `Ping` every 5 s; no inbound frame for 15 s ⇒ session torn down (`ByeReason.Timeout`).

## 4. Authentication (inside the inner TLS channel)

```
V→H  Hello(version, name, nonceV)
H→V  AuthChallenge(hostName, nonceH, salt)
     key = PBKDF2-HMAC-SHA256(normalize(password), salt, 600 000 iterations)        // iterations are a constant, not negotiable
V→H  AuthResponse( HMAC-SHA256(key, "RemoteTool/1 viewer-proof" ‖ ver ‖ nonceV ‖ nonceH ‖ fpViewer ‖ fpHost) )
H→V  AuthResult(ok, HMAC-SHA256(key, "RemoteTool/1 host-proof" ‖ … same inputs …))  // mutual: viewer verifies the host too
V→H  ConsentRequest(wanted permissions)
     … host user clicks Allow/Deny (60 s timeout = deny) …
H→V  ConsentResult(granted, permissions ∩ host policy ∩ requested)
H→V  ScreenInfo, then FrameUpdate / CursorUpdate stream; V→H MouseEvent / KeyEvent
```
`fpViewer`/`fpHost` are the SHA-256 fingerprints of the two TLS certificates *as each side observed them*. A relay (or any
man-in-the-middle) that terminates TLS presents different certificates to each side, so the proofs cannot match and the
host rejects the attempt (tested: `ActiveManInTheMiddleIsDetected`). Comparisons are constant-time. The password is never transmitted or logged.

`password normalize` = upper-case, whitespace and `-` removed. Passwords are 8 chars from a 31-symbol alphabet (≈39.6 bits).

Failure codes: 1 BadPassword, 2 Blocked, 3 Busy, 4 VersionMismatch, 5 NotAllowed. One authentication attempt per connection.

## 5. Relay control protocol (outer link, frames types 0x80–0x8A)

| Type | Name | Payload | Meaning |
|---|---|---|---|
| 0x80 | Register | `u16 ver, str accessKey, str id(9), 16B instanceId` | host announces its ID (long-lived connection) |
| 0x81 | Registered | – | ok |
| 0x82 | IdTaken | – | ID registered by another live host (different instanceId) |
| 0x83 | Denied | – | bad access key / invalid ID / registry full / rate-limited |
| 0x84 | Incoming | `16B token, str viewerAddr` | relay→host: open a data connection |
| 0x85 | Accept | `str accessKey, str id, 16B token` | host's new data connection |
| 0x86 | Connect | `str accessKey, str id` | viewer requests an ID |
| 0x87 | Ready | – | pairing done: from here on the connection is a raw byte pipe |
| 0x88 | NotFound | – | **single generic answer** for unknown ID, offline host, bad key, throttled source, relay full |
| 0x89/0x8A | RelayPing / RelayPong | – | liveness (relay pings every 10 s, drops after 30 s of silence) |

Clients may be configured with several relays: a host registers with the first reachable one (moving on after connect failures); a viewer tries them in order until one answers `Ready`.

After `Ready` the relay sends no more frames on either leg; it only copies bytes (16 KiB buffers) until either side closes or 90 s pass without traffic.
`instanceId` is random per host *process*: same ID + same instanceId = reconnect of the same process (replaces the stale registration);
same ID + different instanceId while the old one is alive = duplicate ⇒ `IdTaken`.

## 6. Permanent (unattended) password mode
`Hello.authMode = 2`. The host answers with `AuthChallenge.salt` = its fixed per-install salt and keeps only `key = PBKDF2(password, salt, 600k)` (protected at rest); the proofs are exactly those of §4, computed with that key. Because
the key is fixed, replay is prevented solely by the fresh nonces and the certificate-fingerprint binding (as in §4). A host that is not the service, has unattended disabled, has no password, or whose breaker is tripped still sends a random
salt and fails the proof like a wrong password — outsiders cannot tell the cases apart.

## 7. Video codecs
Tiles (`FrameUpdate`) are mandatory. H.264 is used only if the viewer offered it, the host has an encoder, and both ends agreed in `ConsentResult.codec`. Either side can force the fallback with `CodecSwitch`; the stream restarts from a keyframe.
Odd frame sizes are cropped by 1 px for NV12.

## 8. Service ⇄ helper protocol (local named pipe, not network)
Same framing, separate type space (`HelperMessage` in `RemoteTool.Service/Helper/HelperProtocol.cs`): requests `GetMonitors, NextFrame, NextH264, GetCursor, GetDesktop, Mouse, Key, ReleaseAll, ShowBanner, HideBanner, AskConsent, Shutdown`;
responses `Monitors, Frame, Video, Cursor, Desktop, ConsentAnswer, Error`; events `EmergencyHotkey, BannerDisconnect`; the helper opens with `Hello(pid, session, h264, user)`. One outstanding request at a time; input messages are fire-and-forget.
The pipe name is random per launch, its ACL admits SYSTEM only, and the service checks that the connecting process id is the one it started.

## 9. Recording file format (`.rtrec`)
`"RTREC001" | u16 version | 8B nonce prefix | bytes(wrapped key)` then records `u32 length | AES-256-GCM(ciphertext ‖ 16B tag)`; nonce = prefix ‖ u32 counter, AAD = header ‖ counter.
Plaintext = `u64 ms | u8 type (1 meta, 2 tile frame, 3 H.264 frame, 4 event, 5 end) | payload`. A missing `End` record means the session or machine crashed.
