using System.Windows;
using RemoteTool.Service.Windows;

namespace RemoteTool.App;

/// <summary>
/// One portable exe, several roles:
///   (none)                  normal UI: Allow Access + Connect
///   --service               Windows service (unattended access)        [started by the SCM]
///   --helper --pipe N ...   per-session helper of the service           [started by the service]
///   --service-setup         elevated window: install/configure the service
///   --service-control X     headless stop|start|remove of the service (used by the MSI)
///   --configure-service ... headless install/configure (Intune/SCCM); secrets via environment variables
///   --bench-codec FILE      write the tile-JPEG vs H.264 comparison to FILE
///   --export-recording F D  decrypt a recording to PNGs / raw H.264 in folder D
///   --verify-audit DIR ROLE check the audit log hash chain
/// </summary>
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        string? Arg(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }

        if (args.Contains("--service")) { RemoteToolWindowsService.RunAsService(); return 0; }
        if (args.Contains("--service-control")) return Cli.ServiceControl(args);
        if (args.Contains("--configure-service")) return Cli.ConfigureService(args);
        if (args.Contains("--bench-codec")) return Cli.BenchCodec(Arg("--bench-codec"));
        if (args.Contains("--export-recording")) return Cli.ExportRecording(args);
        if (args.Contains("--verify-audit")) return Cli.VerifyAudit(args);

        var app = new App();
        app.Mode = args.Contains("--helper") ? AppMode.Helper : args.Contains("--service-setup") ? AppMode.ServiceSetup : AppMode.Normal;
        app.Args = args;
        app.InitializeComponent();
        return app.Run();
    }
}

public enum AppMode { Normal, Helper, ServiceSetup }
