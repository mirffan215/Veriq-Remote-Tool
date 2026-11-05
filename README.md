# RemoteTool

Free, in-house, AnyDesk-style remote support tool: one portable `RemoteTool.exe` (host + viewer) and a small self-hosted relay.
See `docs/` — start with `BUILD.md`, `SECURITY.md`, `DECISIONS.md` (read **D-02** and **D-15** first), `PROTOCOL.md`. Status: Phase 1 (core remote control) and Phase 2 (clipboard, file transfer, multi-monitor, adaptive quality, resume, address book, relay failover) done; Phase 3 (unattended Windows service, H.264, recording, tamper-evident audit log, Arabic/RTL, Intune/signing) implemented — **its Windows-only parts still need the on-Windows validation in `docs/SERVICE.md`**. Target OS: Windows 11 / Server 2022.

**Modes:** internet via relay with a 12-digit code (attended with consent, or unattended Windows service with a permanent password) and local-network mode (direct IP:port, LAN discovery, connect-by-code on the LAN). Security test results: `docs/SECURITY-TEST-REPORT.md`.

**Packaging:** `deploy/RemoteTool.Package` builds the portable single-exe zip; `deploy/RemoteTool.Installer` builds an MSI (WiX). See `docs/BUILD.md`.

## Using it (AnyDesk-style)
1. Start the exe. The top card shows **Your Address** (12 digits). Share it with the person who needs to reach you.
2. To connect to someone: type **their** address under *Remote Address* and press **Connect**. They get an **Accept** prompt (both screens show the same 6-digit security code — compare it).
3. If they gave you a password (Settings → *Access password* on their side), enter it in the optional password box and you connect without a click.
Relay and other technical settings live under *Settings → Advanced* and can be baked into the build (`docs/BUILD.md`, "zero-configuration builds").
