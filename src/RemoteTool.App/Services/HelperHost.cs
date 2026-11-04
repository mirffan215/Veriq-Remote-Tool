using System.IO.Pipes;
using System.Windows;
using System.Windows.Threading;
using RemoteTool.App.Windows;
using RemoteTool.Capture;
using RemoteTool.Core.Session;
using RemoteTool.Input;
using RemoteTool.Service.Helper;
using RemoteTool.Service.Windows;
using RemoteTool.Video;

namespace RemoteTool.App.Services;

/// <summary>
/// The per-session helper (started by the service as SYSTEM inside the console session). Capture and input run on ONE dedicated thread that
/// follows the input desktop (user desktop / login screen / UAC prompt); the banner and consent dialog live on the WPF UI thread.
/// </summary>
internal static class HelperHost
{
    public static void Start(Application app, string[] args)
    {
        string? Arg(string n) { var i = Array.IndexOf(args, n); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        var pipeName = Arg("--pipe") ?? throw new InvalidOperationException("--pipe missing");
        var session = int.TryParse(Arg("--session"), out var s) ? s : 0;
        app.ShutdownMode = ShutdownMode.OnExplicitShutdown;

        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        pipe.Connect(15_000);

        var desktop = new Win32DesktopSwitch();
        var ui = new WpfHelperUi(app.Dispatcher, desktop);
        var thread = new Thread(() =>
        {
            try
            {
                desktop.EnsureInputDesktop(out _);   // bind THIS thread to the input desktop before creating any capture objects
                var producer = new DesktopAwareProducer(desktop, () => new H264FrameProducer(new GdiScreenGrabber(), H264Support.CreateEncoder));
                var injector = new DesktopAwareInjector(desktop, new WindowsInputInjector());
                var endpoint = new HelperEndpoint(pipe, producer, injector, ui, session, Environment.UserName);
                ui.Endpoint = endpoint;
                endpoint.Run(CancellationToken.None);   // returns when the service closes the pipe or says Shutdown
            }
            finally { app.Dispatcher.InvokeShutdown(); }
        }) { IsBackground = true, Name = "RemoteTool helper endpoint" };
        thread.SetApartmentState(ApartmentState.MTA);
        thread.Start();
    }
}

internal sealed class WpfHelperUi : IHelperUi
{
    private readonly Dispatcher _ui;
    private readonly Win32DesktopSwitch _desktop;
    private BannerWindow? _banner;
    private HotKeyListener? _hotkey;

    public HelperEndpoint? Endpoint { get; set; }

    public WpfHelperUi(Dispatcher ui, Win32DesktopSwitch desktop) { _ui = ui; _desktop = desktop; }

    // Called on the endpoint thread, which is the one attached to the input desktop.
    public string CurrentInputDesktop() => _desktop.EnsureInputDesktop(out _);

    public void ShowBanner(string viewer, bool recording) => _ui.InvokeAsync(() =>
    {
        Close();
        _banner = new BannerWindow(viewer, () => Endpoint?.NotifyBannerDisconnect(), null, recording);
        _banner.Show();
        _hotkey = new HotKeyListener(() => Endpoint?.NotifyEmergencyHotkey());
    });

    public void HideBanner() => _ui.InvokeAsync(Close);

    private void Close()
    {
        _banner?.Close();
        _banner = null;
        _hotkey?.Dispose();
        _hotkey = null;
    }

    public Task<ConsentDecision> AskConsentAsync(ConsentRequestInfo info) => _ui.InvokeAsync(() =>
    {
        var w = new ConsentWindow(info);
        var timeout = new DispatcherTimer { Interval = TimeSpan.FromSeconds(60) };   // never leave a stale dialog behind: no answer = deny
        timeout.Tick += (_, _) => { timeout.Stop(); w.Close(); };
        timeout.Start();
        w.ShowDialog();
        timeout.Stop();
        return w.Decision;
    }).Task;
}
