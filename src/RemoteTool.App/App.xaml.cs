using System.Windows;
using RemoteTool.App.Localization;
using RemoteTool.App.Services;
using RemoteTool.App.Windows;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Security;

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
        EditionCustomization.Startup(this);
        if (Mode == AppMode.Helper) { Services.HelperHost.Start(this, Args); return; }   // no UI of its own: banner/consent only when the service asks
        if (Mode == AppMode.ServiceSetup)
        {
            ShutdownMode = ShutdownMode.OnMainWindowClose;
            MainWindow = new ServiceSetupWindow();
            MainWindow.Show();
            return;
        }
        _single = new Mutex(true, @"Local\" + EditionInfo.Current.DataFolder + ".SingleInstance", out var first);
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
        // Zero setup for users: company relay defaults (env/args > file next to exe > built into the exe) fill only EMPTY settings.
        var defaults = DefaultsLoader.Load(exeDir, e.Args);
        if (defaults.ApplyTo(store.Current, new DpapiProtector())) store.Save();

        var hostAudit = new JsonlAuditLog(paths.LogDirectory, "host");
        var viewerAudit = new JsonlAuditLog(paths.LogDirectory, "viewer");
        hostAudit.Write("app_start", ("version", typeof(App).Assembly.GetName().Version?.ToString()), ("portable", paths.Portable));
        hostAudit.Write("id_issued", ("id", store.Current.Id), ("firstRun", firstRun));

        var protector = new DpapiProtector();
        ApplyLanguage(store.Current.Language);
        ThemeManager.Apply(store.Current.Theme);
        var access = new PermanentPasswordStore(Path.Combine(paths.SettingsDirectory, "access.json"), protector);   // optional "access password" of this PC
        _host = new HostController(Dispatcher, store, protector, hostAudit, paths.ReceivedFilesDirectory, access);
        _host.ApplySettings();
        var viewer = new ViewerLauncher(store, protector, viewerAudit, new UiFilePrompt(Dispatcher), paths.ReceivedFilesDirectory);
        MainWindow = new MainWindow(store, protector, _host, viewer, access);
        MainWindow.Show();
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
