using System.Runtime.Versioning;
using System.ServiceProcess;
using RemoteTool.Core.Audit;

namespace RemoteTool.Service.Windows;

/// <summary>Thin SCM shell around <see cref="ServiceRuntime"/> (all logic lives there and is tested cross-platform).</summary>
[SupportedOSPlatform("windows")]
public sealed class RemoteToolWindowsService : ServiceBase
{
    private ServiceRuntime? _runtime;

    public RemoteToolWindowsService()
    {
        ServiceName = ScCommands.ServiceName;
        CanStop = true;
        CanShutdown = true;
        CanHandleSessionChangeEvent = true;  // logon/logoff/lock/fast-user-switch => move the helper
        AutoLog = true;
    }

    protected override void OnStart(string[] args)
    {
        var paths = ServicePaths.Default();
        try
        {
            var audit = new JsonlAuditLog(paths.LogDir, "service");
            var exe = Environment.ProcessPath ?? ServiceInstaller.InstalledExe;
            _runtime = new ServiceRuntime(paths, new MachineDpapiProtector(), new WtsHelperLauncher(exe, audit), new WindowsSasSender(), audit);
            _runtime.Start();
        }
        catch (Exception e)
        {
            EventLog.WriteEntry("RemoteTool service failed to start: " + e.GetType().Name + ": " + e.Message, System.Diagnostics.EventLogEntryType.Error);
            ExitCode = 1;
            throw; // SCM reports the failure; recovery actions restart us
        }
    }

    protected override void OnSessionChange(SessionChangeDescription changeDescription) => _runtime?.NotifySessionChanged();

    protected override void OnStop()
    {
        var r = _runtime;
        _runtime = null;
        if (r is not null) r.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(20));
    }

    protected override void OnShutdown() => OnStop();

    /// <summary>Entry point used by <c>RemoteTool.exe --service</c>.</summary>
    public static void RunAsService() => Run(new RemoteToolWindowsService());
}
