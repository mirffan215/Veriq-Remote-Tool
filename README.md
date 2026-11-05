# RemoteTool

Free, in-house, AnyDesk-style remote support tool: one portable `RemoteTool.exe` (host + viewer) and a small self-hosted relay.
See `docs/` — start with `BUILD.md`, `SECURITY.md`, `DECISIONS.md` (read **D-02** and **D-15** first), `PROTOCOL.md`. Status: Phase 1 (core remote control) and Phase 2 (clipboard, file transfer, multi-monitor, adaptive quality, resume, address book, relay failover) done; Phase 3 (unattended Windows service, H.264, recording, tamper-evident audit log, Arabic/RTL, Intune/signing) implemented — **its Windows-only parts still need the on-Windows validation in `docs/SERVICE.md`**. Target OS: Windows 10 (1809) / Server 2019 and newer.

**Modes:** internet via relay with a 12-digit code (attended with consent, or unattended Windows service with a permanent password) and local-network mode (direct IP:port, LAN discovery, connect-by-code on the LAN). Security test results: `docs/SECURITY-TEST-REPORT.md`.

**Packaging:** `deploy/RemoteTool.Package` builds the portable single-exe zip; `deploy/RemoteTool.Installer` builds an MSI (WiX). See `docs/BUILD.md`.

## Using it (AnyDesk-style)
1. Start the exe. The top card shows **Your Address** (12 digits). Share it with the person who needs to reach you.
2. To connect to someone: type **their** address under *Remote Address* and press **Connect**. They get an **Accept** prompt (both screens show the same 6-digit security code — compare it).
3. If they gave you a password (Settings → *Access password* on their side), enter it in the optional password box and you connect without a click.
Relay and other technical settings live under *Settings → Advanced* and can be baked into the build (`docs/BUILD.md`, "zero-configuration builds").

### Local network: finding computers and the firewall
* **Main window → On this network:** *Find PCs on this network* lists RemoteTool PCs that announce themselves. *Scan range* checks internal addresses for the RemoteTool port (21118): enter networks (`10.10.5.0/24`), ranges (`10.10.5.10-10.10.5.50`), IP addresses or computer names (`pc01.corp.local`); empty = your own subnet(s). Results show the computer name (reverse DNS) and IP:port; double-click one to fill the connect box.
* The scan is user-started, private address space only (10.x, 172.16-31.x, 192.168.x, never the internet), at most 4096 addresses, TCP connect only. An open port proves nothing about who is behind it; the connection still needs Accept or a password.
* **Settings → Advanced → Windows Firewall:** *Open firewall for RemoteTool* (UAC prompt) adds inbound rules for this exe only (TCP 21118 + UDP 21119 discovery), Private/Domain networks only, from your own subnet; tick *Also allow other internal networks* when computers are on different subnets. *Remove firewall rules* undoes it. Command line (elevated): `RemoteTool.exe --firewall add [--wide] [--port N]` / `remove`. The rule is tied to the exe's path: if you move the exe, run it again.
