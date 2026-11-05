# Editions: Enterprise, Production, UAT (one source, three products)

```
RemoteTool.sln                 = the FULL project (all source, tests, tools, packages and the three editions)
src\...                        = the shared code (security, protocol, relay, app) - change it once, every edition gets it
editions\
  Edition.Package.targets      = shared build logic (publishes the app as one exe for an edition)
  Enterprise\  edition.props  RemoteTool.ico  Customization\*.cs   RemoteTool.Enterprise.csproj
  Production\  edition.props  RemoteTool.ico                       RemoteTool.Production.csproj
  UAT\         edition.props  RemoteTool.ico                       RemoteTool.UAT.csproj
```

| | Enterprise | Production | UAT |
|---|---|---|---|
| Exe | `VeriqRemoteTool-Enterprise.exe` | `ToolVeriq.exe` | `ToolVeriq-UAT.exe` |
| Window title | Veriq Remote Tool Enterprise [Enterprise] | Veriq Remote Tool | Veriq Remote Tool [UAT] |
| Icon | purple + gold star | blue | amber + "UAT" tag |
| Settings / logs folder | `%AppData%\VeriqRemoteTool-Enterprise` | `%AppData%\VeriqRemoteTool` | `%AppData%\VeriqRemoteTool-UAT` |
| Own code | `editions\Enterprise\Customization\*.cs` | - | - |
| Relay defaults | `RT_ENTERPRISE_RELAY*` | `RT_PROD_RELAY*` | `RT_UAT_RELAY*` |

Because every edition has its own data folder, single-instance lock and exe name, **Production and UAT can run side by side on one PC** without sharing an ID, settings or logs.

## Build
```powershell
dotnet build editions\UAT -c Release            # one edition  -> artifacts\UAT\ToolVeriq-UAT.exe (+ .sha256, README.txt, artifacts\UAT-<version>-win-x64.zip)
dotnet build editions\Production -c Release
dotnet build editions\Enterprise -c Release
powershell -ExecutionPolicy Bypass -File scripts\build-editions.ps1             # all three, tests first
powershell -ExecutionPolicy Bypass -File scripts\build-editions.ps1 -Edition UAT -SkipTests
```
Visual Studio: right-click an edition project → Build. *Build Solution* deliberately does **not** package editions (they share the app's build folders and must run one after another).
Relay defaults per edition (never stored in the repository):
```powershell
$env:RT_UAT_RELAY = "uat-relay.example.com:8443"; $env:RT_UAT_RELAY_FP = "AABB..."; $env:RT_UAT_RELAY_KEY = "..."
$env:RT_PROD_RELAY = "relay.example.com:8443";     $env:RT_PROD_RELAY_KEY = "..."
```

## "I want to change only one project"
* **Look, name, icon, relay, folder of one edition:** edit that edition's `edition.props` / `RemoteTool.ico`. Nothing else changes.
* **Code that only one edition should have:** add `.cs` files to `editions\<Edition>\Customization\`. They are compiled only into that edition. Hook point: `EditionCustomization.OnStartup(App app)` (see `editions\Enterprise\Customization\EnterpriseCustomization.cs`). Other editions never contain that code.
* **A feature or fix for everyone:** change `src\...` once; rebuild the editions you want to ship.
* **UAT first, then Production:** build UAT from the commit under test, test it, then build Production from the *same commit* (tag it, e.g. `git tag release-0.1.0`).
* **Branching (optional):** keep one `main`; release by tag. If Production must lag UAT, build Production from the older tag instead of copying code.

## Why not three copies of the code?
Copying the source three times means every security fix (TLS policy, handshake, relay) must be applied three times, and the copies drift apart. For a remote-control tool that is the wrong risk. Editions give you what you asked for (separate products you can customise and release independently) with one copy of the security-critical code. If you ever need a hard split (separate repo per product), `git subtree`/a fork can do it later.

## Limits (be aware)
* The **unattended Windows service** and the **MSI** are not edition-aware yet: the service name (`RemoteToolService`), install folder and firewall rule names are shared, so install the service from **one** edition per PC. The portable exe, settings, logs, firewall rule created from Settings and single-instance lock are per edition on the exe side except the rule names (the rule is tied to the exe path, so each edition's exe gets its own effective rule when set up from that exe).
* Windows-only parts (WPF, icons in Explorer, packaging of the real app) were verified here only by tests and a stub build of the packaging targets; build once on Windows and run `--tls-selftest`.
* Windows may cache Explorer icons: rename the file or restart Explorer if an old icon shows.
