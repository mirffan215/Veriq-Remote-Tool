using System.Runtime.Versioning;
using RemoteTool.Core.Config;
using RemoteTool.Core.Security;
using RemoteTool.Service.Windows;

namespace RemoteTool.Service;

public sealed record ServiceSetupInput(string RelayAddress, string? RelayKey, string Fingerprint, string DisplayName, bool Enabled,
    bool ConsentWhenUserPresent, bool Record, int RetentionDays, string? NewPermanentPassword);

/// <summary>Elevated configuration of the unattended-access service. Order matters: ACL-protected folders exist before any secret is written.</summary>
[SupportedOSPlatform("windows")]
public static class ServiceSetup
{
    public static string Apply(ServiceSetupInput i, Action<string> log)
    {
        if (!ServiceInstaller.IsAdministrator()) throw new UnauthorizedAccessException("Administrator rights are required.");
        var paths = ServicePaths.Default();
        var prot = new MachineDpapiProtector();

        // 1. install (creates the locked-down folders, copies the exe to Program Files, creates and starts the service with unattended OFF)
        if (!ServiceInstaller.IsInstalled() || ServiceInstaller.InstalledExe != Environment.ProcessPath) ServiceInstaller.Install(paths, log);

        // 2. configuration + permanent password
        var perm = new PermanentPasswordStore(paths.PermanentFile, prot);
        if (!string.IsNullOrEmpty(i.NewPermanentPassword)) { perm.Set(i.NewPermanentPassword); log("Permanent password updated."); }
        if (i.Enabled && !perm.Enabled) throw new InvalidOperationException("Set a permanent password before enabling unattended access.");

        var store = new ServiceConfigStore(paths.ConfigFile);
        var cfg = store.Load();
        cfg.RelayAddress = i.RelayAddress.Trim();
        cfg.RelayFingerprint = i.Fingerprint.Trim();
        if (!string.IsNullOrEmpty(i.RelayKey)) cfg.RelayAccessKeyProtected = prot.Protect(i.RelayKey);
        cfg.DisplayName = NameClean(i.DisplayName);
        cfg.UnattendedEnabled = i.Enabled;
        cfg.ConsentWhenUserPresent = i.ConsentWhenUserPresent;
        cfg.RecordSessions = i.Record;
        cfg.RecordingRetentionDays = Math.Clamp(i.RetentionDays, 1, 3650);
        store.Save(cfg);

        // 3. make the service pick it up
        ServiceInstaller.Restart(log);
        return cfg.Id;
    }

    private static string NameClean(string s) => RemoteTool.Core.Session.NameSanitizer.Clean(s, Environment.MachineName);
}

/// <summary>Lets the normal (user-mode) UI notice that the service owns this PC's identity, so it does not register a second ID.</summary>
[SupportedOSPlatform("windows")]
public static class ServiceStatus
{
    public sealed record Info(string Id, string Relay, bool UnattendedEnabled, bool PermanentPasswordSet);

    public static bool IsRunning()
    {
        try
        {
            using var sc = new System.ServiceProcess.ServiceController(ScCommands.ServiceName);
            return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
        }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { return false; } // not installed
    }

    public static Info? Read()
    {
        if (!IsRunning()) return null;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(ServicePaths.Default().PublicStatusFile));
            var r = doc.RootElement;
            return new Info(r.GetProperty("id").GetString() ?? "", r.GetProperty("relay").GetString() ?? "",
                r.GetProperty("unattendedEnabled").GetBoolean(), r.GetProperty("permanentPasswordSet").GetBoolean());
        }
        catch (Exception e) when (e is IOException or System.Text.Json.JsonException or KeyNotFoundException or UnauthorizedAccessException) { return null; }
    }
}

/// <summary>
/// Headless configuration for software-distribution tools (Intune, SCCM, scripts):
/// <c>RemoteTool.exe --configure-service --relay host:443 [--relay-fp HEX] [--relay-key-env VAR] [--password-env VAR] [--name N]
/// [--enable] [--no-user-consent] [--record] [--retention-days 30]</c>.
/// Secrets are read from environment variables named on the command line, never from the command line itself (process lists are readable).
/// </summary>
public static class ServiceSetupArgs
{
    public static (ServiceSetupInput? Input, string? Error) Parse(string[] args, Func<string, string?> env)
    {
        string? Arg(string n) { var i = Array.IndexOf(args, n); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        bool Has(string n) => Array.IndexOf(args, n) >= 0;

        var relay = Arg("--relay") ?? "";
        if (relay.Length > 0 && !RemoteTool.Core.Relay.RelayEndpoint.TryParseList(relay, "", "", out _)) return (null, "--relay must look like host:port[,host:port]");

        string? Secret(string flag)
        {
            var name = Arg(flag);
            if (name is null) return null;
            var v = env(name);
            return string.IsNullOrEmpty(v) ? throw new ArgumentException($"environment variable '{name}' (from {flag}) is empty or not set") : v;
        }

        try
        {
            var password = Secret("--password-env");
            if (password is not null && PermanentPasswordStore.Validate(password) is { } problem) return (null, "permanent password rejected: " + problem);
            var enable = Has("--enable");
            if (enable && password is null) return (null, "--enable needs --password-env (a permanent password must exist before unattended access can be enabled)");
            var days = int.TryParse(Arg("--retention-days"), out var d) ? d : 30;
            return (new ServiceSetupInput(relay, Secret("--relay-key-env"), Arg("--relay-fp") ?? "", Arg("--name") ?? Environment.MachineName, enable,
                ConsentWhenUserPresent: !Has("--no-user-consent"), Record: Has("--record"), RetentionDays: days, NewPermanentPassword: password), null);
        }
        catch (ArgumentException e) { return (null, e.Message); }
    }
}
