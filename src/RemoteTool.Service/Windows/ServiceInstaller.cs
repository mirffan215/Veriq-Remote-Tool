using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace RemoteTool.Service.Windows;

/// <summary>The exact <c>sc.exe</c> invocations (pure, unit-tested). Arguments are passed as an array: no shell quoting accidents.</summary>
public static class ScCommands
{
    public const string ServiceName = "RemoteToolService";
    public const string DisplayName = "RemoteTool Unattended Access";

    public static IReadOnlyList<string[]> Create(string exePath) => new[]
    {
        new[] { "create", ServiceName, "binPath=", $"\"{exePath}\" --service", "start=", "delayed-auto", "obj=", "LocalSystem", "DisplayName=", DisplayName },
        new[] { "description", ServiceName, "Lets authorised IT staff reach this PC (including the login screen) with a permanent password. Opt-in; see RemoteTool documentation." },
        // restart after 5 s, 5 s, 60 s; reset the failure counter after a day
        new[] { "failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000" },
        new[] { "sidtype", ServiceName, "unrestricted" },
    };

    public static string[] Start() => new[] { "start", ServiceName };
    public static string[] Stop() => new[] { "stop", ServiceName };
    public static string[] Delete() => new[] { "delete", ServiceName };
}

/// <summary>
/// Installs/uninstalls the service. Installation COPIES the exe into %ProgramFiles% (admin-writable only): a SYSTEM service must never run a
/// binary from a user-writable folder, otherwise any user could replace it and get SYSTEM. Data folder ACLs: SYSTEM + Administrators only.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceInstaller
{
    public static string InstallDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "RemoteTool");
    public static string InstalledExe => Path.Combine(InstallDirectory, "RemoteTool.exe");

    public static bool IsAdministrator() => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    public static void Install(ServicePaths paths, Action<string> log)
    {
        if (!IsAdministrator()) throw new UnauthorizedAccessException("Administrator rights are required.");
        var source = Environment.ProcessPath ?? throw new InvalidOperationException("unknown exe path");

        if (IsInstalled()) { Run(ScCommands.Stop(), log, ignoreErrors: true); WaitStopped(); }
        Directory.CreateDirectory(InstallDirectory);
        LockDown(InstallDirectory, usersMayRead: true);
        if (!string.Equals(Path.GetFullPath(source), Path.GetFullPath(InstalledExe), StringComparison.OrdinalIgnoreCase))
            File.Copy(source, InstalledExe, overwrite: true);
        log($"Installed {InstalledExe}");

        Directory.CreateDirectory(paths.ServiceDir);
        LockDown(paths.ServiceDir, usersMayRead: false);        // config, permanent-password key, logs, recordings
        Directory.CreateDirectory(paths.PublicDir);
        LockDown(paths.PublicDir, usersMayRead: true);          // non-sensitive status only

        if (!IsInstalled()) foreach (var cmd in ScCommands.Create(InstalledExe)) Run(cmd, log);
        Run(ScCommands.Start(), log);
    }

    /// <summary>
    /// Stops and deletes the service and removes its firewall rules, but leaves the program folder and all data alone. Used by the MSI uninstall
    /// (Windows Installer removes the files itself) and by <see cref="Uninstall"/>.
    /// </summary>
    public static void RemoveService(Action<string> log)
    {
        if (!IsAdministrator()) throw new UnauthorizedAccessException("Administrator rights are required.");
        if (IsInstalled()) { Run(ScCommands.Stop(), log, ignoreErrors: true); WaitStopped(); Run(ScCommands.Delete(), log, ignoreErrors: true); }
        FirewallRules.Apply(InstalledExe, 0, 0, enable: false, log);
    }

    public static void Uninstall(ServicePaths paths, bool purgeData, Action<string> log)
    {
        RemoveService(log);
        try { if (Directory.Exists(InstallDirectory)) Directory.Delete(InstallDirectory, true); } catch (IOException) { log("Could not remove the install folder yet (helper still exiting); remove it manually."); }
        if (purgeData && Directory.Exists(paths.ServiceDir)) Directory.Delete(paths.ServiceDir, true);
    }

    public static void Stop(Action<string> log) { Run(ScCommands.Stop(), log, ignoreErrors: true); WaitStopped(); }
    public static void Start(Action<string> log) => Run(ScCommands.Start(), log, ignoreErrors: true);

    public static void Restart(Action<string> log)
    {
        Run(ScCommands.Stop(), log, ignoreErrors: true);
        WaitStopped();
        Run(ScCommands.Start(), log);
    }

    public static bool IsInstalled() => Query().Contains("SERVICE_NAME", StringComparison.OrdinalIgnoreCase);
    public static bool IsRunning() => Query().Contains("RUNNING", StringComparison.OrdinalIgnoreCase);

    private static string Query()
    {
        try { return Run(new[] { "query", ScCommands.ServiceName }, _ => { }, ignoreErrors: true); } catch (System.ComponentModel.Win32Exception) { return ""; }
    }

    private static void WaitStopped()
    {
        for (var i = 0; i < 30 && IsRunning(); i++) Thread.Sleep(500);
    }

    private static string Run(string[] args, Action<string> log, bool ignoreErrors = false)
    {
        var psi = new ProcessStartInfo("sc.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        p.WaitForExit();
        if (p.ExitCode != 0 && !ignoreErrors) throw new InvalidOperationException($"sc {string.Join(' ', args)} failed ({p.ExitCode}): {output.Trim()}");
        log($"sc {args[0]} -> {p.ExitCode}");
        return output;
    }

    /// <summary>Protected ACL (no inheritance): SYSTEM and Administrators full control; optionally Users read/execute.</summary>
    private static void LockDown(string dir, bool usersMayRead)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (usersMayRead)
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, inherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(dir).SetAccessControl(sec);
    }
}

/// <summary>
/// Windows Firewall rules for the LAN option. Inbound is allowed ONLY for this program, ONLY on Private and Domain networks (never Public) and ONLY from
/// the local subnet. Internet-only installs add no inbound rule at all.
/// </summary>
public static class FirewallCommands
{
    public const string TcpRule = "RemoteToolLAN-TCP", UdpRule = "RemoteToolLAN-Discovery";

    /// <summary>"Also allow other internal subnets": the three private address blocks. Still never Public networks, never the internet.</summary>
    public const string PrivateRanges = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

    public static IReadOnlyList<string[]> Add(string exePath, int tcpPort, int udpPort, bool allowOtherInternalSubnets = false)
    {
        var remote = allowOtherInternalSubnets ? PrivateRanges : "localsubnet";
        return new[]
        {
            Rule(TcpRule, exePath, "TCP", tcpPort, remote),
            Rule(UdpRule, exePath, "UDP", udpPort, remote),
        };
    }

    public static IReadOnlyList<string[]> Remove() => new[]
    {
        new[] { "advfirewall", "firewall", "delete", "rule", $"name={TcpRule}" },
        new[] { "advfirewall", "firewall", "delete", "rule", $"name={UdpRule}" },
    };

    private static string[] Rule(string name, string exe, string proto, int port, string remote) => new[]
    {
        "advfirewall", "firewall", "add", "rule", $"name={name}", "dir=in", "action=allow", $"program={exe}", $"protocol={proto}",
        $"localport={port}", "profile=private,domain", $"remoteip={remote}", "enable=yes",
    };
}

[SupportedOSPlatform("windows")]
public static class FirewallRules
{
    public static void Apply(string exePath, int tcpPort, int udpPort, bool enable, Action<string> log, bool allowOtherInternalSubnets = false)
    {
        foreach (var rm in FirewallCommands.Remove()) Run(rm, log);          // idempotent: replace any previous rule
        if (!enable) return;
        foreach (var add in FirewallCommands.Add(exePath, tcpPort, udpPort, allowOtherInternalSubnets)) Run(add, log);
    }

    private static void Run(string[] args, Action<string> log)
    {
        var psi = new System.Diagnostics.ProcessStartInfo("netsh.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        log($"netsh {args[2]} {args[3]} -> {p.ExitCode}");
    }
}
