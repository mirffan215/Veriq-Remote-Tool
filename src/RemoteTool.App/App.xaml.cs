using System.Windows;
using RemoteTool.App.Localization;
using RemoteTool.App.Services;
using RemoteTool.App.Windows;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;

namespace RemoteTool.App;

public partial class App : Application
{
    private Mutex? _single;
    private HostController? _host;

    public AppMode Mode { get; set; }
    public string[] Args { get; set; } = Array.Empty<string>();

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (Mode == AppMode.Helper) { Services.HelperHost.Start(this, Args); return; }   // no UI of its own: banner/consent only when the service asks
        if (Mode == AppMode.ServiceSetup)
        {
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            MainWindow = new ServiceSetupWindow();
            MainWindow.Show();
            return;
        }
        _single = new Mutex(true, @"Local\RemoteTool.SingleInstance", out var first);
        if (!first)
        {
            MessageBox.Show(Loc.T("Already_Running"), Loc.T("App_Title"));
            Shutdown();
            return;
        }

        var exeDir = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
        var paths = StoragePaths.Detect(exeDir);
        var firstRun = !File.Exists(paths.SettingsFile);
        var store = new SettingsStore(paths.SettingsFile);
        store.Load();
        ApplyDeploymentDefaults(store, e.Args);

        var hostAudit = new JsonlAuditLog(paths.LogDirectory, "host");
        var viewerAudit = new JsonlAuditLog(paths.LogDirectory, "viewer");
        hostAudit.Write("app_start", ("version", typeof(App).Assembly.GetName().Version?.ToString()), ("portable", paths.Portable));
        hostAudit.Write("id_issued", ("id", store.Current.Id), ("firstRun", firstRun));

        var protector = new DpapiProtector();
        ApplyLanguage(store.Current.Language);
        ThemeManager.Apply(store.Current.Theme);
        _host = new HostController(Dispatcher, store, protector, hostAudit, paths.ReceivedFilesDirectory);
        _host.ApplySettings();
        var viewer = new ViewerLauncher(store, protector, viewerAudit, new UiFilePrompt(Dispatcher), paths.ReceivedFilesDirectory);
        MainWindow = new MainWindow(store, protector, _host, viewer);
        MainWindow.Show();
    }

    /// <summary>
    /// Zero-touch deployment: relay settings may come from environment variables (preferred for secrets) or command line:
    /// REMOTETOOL_RELAY, REMOTETOOL_RELAY_KEY, REMOTETOOL_RELAY_FP  /  --relay host:port --relay-key K --relay-fp HEX.
    /// Only applied when the corresponding setting is still empty, so user changes are never overwritten.
    /// </summary>
    private static void ApplyDeploymentDefaults(SettingsStore store, string[] args)
    {
        string? Arg(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        var s = store.Current;
        var relay = Arg("--relay") ?? Environment.GetEnvironmentVariable("REMOTETOOL_RELAY");
        var key = Arg("--relay-key") ?? Environment.GetEnvironmentVariable("REMOTETOOL_RELAY_KEY");
        var fp = Arg("--relay-fp") ?? Environment.GetEnvironmentVariable("REMOTETOOL_RELAY_FP");
        var changed = false;
        if (string.IsNullOrEmpty(s.RelayAddress) && !string.IsNullOrWhiteSpace(relay)) { s.RelayAddress = relay.Trim(); changed = true; }
        if (string.IsNullOrEmpty(s.RelayAccessKeyProtected) && !string.IsNullOrWhiteSpace(key)) { s.RelayAccessKeyProtected = new DpapiProtector().Protect(key); changed = true; }
        if (string.IsNullOrEmpty(s.RelayFingerprint) && !string.IsNullOrWhiteSpace(fp)) { s.RelayFingerprint = fp.Trim(); changed = true; }
        if (changed) store.Save();
    }

    /// <summary>"ar" / "en" / "System". Resources fall back to English for any missing key; RTL layout follows the culture.</summary>
    private static void ApplyLanguage(string setting)
    {
        if (setting is not ("ar" or "en")) return;
        var c = new System.Globalization.CultureInfo(setting);
        System.Globalization.CultureInfo.DefaultThreadCurrentUICulture = c;
        System.Globalization.CultureInfo.CurrentUICulture = c;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _host?.DisposeAsync().AsTask().Wait(TimeSpan.FromSeconds(5));
        _single?.Dispose();
        base.OnExit(e);
    }
}
