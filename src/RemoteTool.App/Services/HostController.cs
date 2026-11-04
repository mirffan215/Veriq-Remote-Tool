using RemoteTool.Service;
using System.Windows;
using System.Windows.Threading;
using RemoteTool.App.Windows;
using RemoteTool.Capture;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;
using RemoteTool.Input;

namespace RemoteTool.App.Services;

/// <summary>Glue between the UI-free <see cref="HostService"/> and WPF: consent dialog, banner, emergency hotkey, settings.</summary>
public sealed class HostController : IAsyncDisposable
{
    private readonly Dispatcher _ui;
    private readonly SettingsStore _store;
    private readonly ISecretProtector _protector;
    private readonly IAuditLog _audit;
    private BannerWindow? _banner;
    private HotKeyListener? _hotkey;
    private string _relayKey = "";

    public HostService Service { get; }
    public string? LastError { get; private set; }
    public event Action? StateChanged;

    public HostController(Dispatcher ui, SettingsStore store, ISecretProtector protector, IAuditLog audit, string receiveDir)
    {
        _ui = ui;
        _store = store;
        _protector = protector;
        _audit = audit;
        Service = new HostService(
            () => new RemoteTool.Video.H264FrameProducer(new GdiScreenGrabber(),
                (int w, int h, int fps, int kbps, out string? err) => store.Current.EnableH264 ? RemoteTool.Video.H264Support.CreateEncoder(w, h, fps, kbps, out err) : NoEncoder(out err)),
            () => new WindowsInputInjector(),
            new UiConsent(ui),
            audit,
            BuildPolicy(),
            clipboardFactory: () => new WindowsClipboard(),
            filePrompt: new UiFilePrompt(ui),
            receiveDirectory: receiveDir);
        Service.PasswordChanged += RaiseChanged;
        Service.RelayStatusChanged += _ => RaiseChanged();
        Service.IdRegenerated += _ => RaiseChanged();
        Service.SessionStarted += s => _ui.InvokeAsync(() => OnSessionStarted(s));
        Service.SessionEnded += (_, _) => _ui.InvokeAsync(OnSessionEnded);
    }

    private static RemoteTool.Video.IH264Encoder? NoEncoder(out string? err) { err = "H.264 disabled in settings"; return null; }

    /// <summary>True when the Windows service owns this PC's identity (ID, relay registration, unattended access).</summary>
    public bool ServiceManaged { get; private set; }

    private HostPolicy BuildPolicy()
    {
        var s = _store.Current;
        return new HostPolicy(s.DisplayName, s.ViewOnly, s.AllowClipboard, s.AllowFileTransfer, s.IpAllowList.ToArray());
    }

    private void RaiseChanged() => _ui.InvokeAsync(() => StateChanged?.Invoke());

    /// <summary>Applies persisted settings: policy immediately; relay/listener only if their settings changed.</summary>
    public void ApplySettings()
    {
        var s = _store.Current;
        Service.Policy = BuildPolicy();

        // If the unattended-access service is running it already registers an ID with the relay; a second registration from this
        // user-mode process would create a second, differently-protected way in. Step aside and let the UI show the service's ID.
        ServiceManaged = ServiceStatus.IsRunning();
        if (ServiceManaged)
        {
            if (Service.RelayStatus != RelayStatus.Disabled) _ = Service.StopRelayAsync();
            if (Service.DirectListening) Service.StopDirectListener();
            _relayKey = "";
            RaiseChanged();
            return;
        }

        var key = string.IsNullOrEmpty(s.RelayAccessKeyProtected) ? "" : _protector.Unprotect(s.RelayAccessKeyProtected);
        var relayWanted = RelayEndpoint.TryParseList(s.RelayAddress, key, s.RelayFingerprint, out var relays);
        var fingerprint = $"{s.RelayAddress}|{key}|{s.RelayFingerprint}";
        if (relayWanted && (fingerprint != _relayKey || Service.RelayStatus == RelayStatus.Disabled))
        {
            _relayKey = fingerprint;
            Service.StartRelay(relays, new SettingsIdProvider(_store));
        }
        else if (!relayWanted && Service.RelayStatus != RelayStatus.Disabled)
        {
            _relayKey = "";
            _ = Service.StopRelayAsync();
        }

        LastError = null;
        try
        {
            if (s.DirectListenerEnabled && (!Service.DirectListening)) Service.StartDirectListener(s.DirectPort);
            else if (!s.DirectListenerEnabled && Service.DirectListening) Service.StopDirectListener();
        }
        catch (Exception e) when (e is System.Net.Sockets.SocketException or InvalidOperationException)
        {
            LastError = e.Message;
            s.DirectListenerEnabled = false;
            _store.Save();
        }
        RaiseChanged();
    }

    public void AuditSettingsChanged()
    {
        var s = _store.Current;
        _audit.Write("permission_change", ("viewOnly", s.ViewOnly), ("clipboard", s.AllowClipboard), ("fileTransfer", s.AllowFileTransfer),
            ("directListener", s.DirectListenerEnabled), ("allowListEntries", s.IpAllowList.Count));
    }

    /// <summary>Re-register with the relay under the (new) persisted ID.</summary>
    public void RestartRelayRegistration()
    {
        _relayKey = "";
        _audit.Write("id_issued", ("id", _store.Current.Id), ("firstRun", false), ("reason", "user-regenerated"));
        ApplySettings();
    }

    /// <summary>Restart the direct listener (port changed).</summary>
    public void RestartDirectListener()
    {
        Service.StopDirectListener();
        ApplySettings();
    }

    private void OnSessionStarted(SessionInfo s)
    {
        _banner = new BannerWindow(s.ViewerName, () => Service.DisconnectActive(ByeReason.HostDisconnected),
            (s.Permissions & Permissions.FileTransfer) != 0 ? SendFileToViewer : null);
        _banner.Show();
        _hotkey = new HotKeyListener(() => Service.DisconnectActive(ByeReason.Emergency));
        if (!_hotkey.Registered) _audit.Write("hotkey_unavailable");
        StateChanged?.Invoke();
    }

    private async void SendFileToViewer()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog();
        if (dlg.ShowDialog() != true) return;
        var outcome = await Service.SendFileAsync(dlg.FileName);
        MessageBox.Show(Localization.Loc.T(outcome switch
        {
            FileSendOutcome.Completed => "File_Sent", FileSendOutcome.Rejected => "File_Declined", FileSendOutcome.HashMismatch => "File_Hash",
            FileSendOutcome.Cancelled => "File_Cancelled", _ => "File_Failed",
        }), Localization.Loc.T("App_Title"));
    }

    private void OnSessionEnded()
    {
        _banner?.Close();
        _banner = null;
        _hotkey?.Dispose();
        _hotkey = null;
        StateChanged?.Invoke();
    }

    public async ValueTask DisposeAsync()
    {
        await Service.DisposeAsync();
        await _ui.InvokeAsync(() => { _banner?.Close(); _hotkey?.Dispose(); });
    }

    private sealed class UiConsent : IConsentProvider
    {
        private readonly Dispatcher _ui;
        public UiConsent(Dispatcher ui) { _ui = ui; }

        public Task<ConsentDecision> RequestAsync(ConsentRequestInfo info, CancellationToken ct)
            => _ui.InvokeAsync(() =>
            {
                var w = new ConsentWindow(info);
                using var reg = ct.Register(() => w.Dispatcher.InvokeAsync(() => w.Close())); // timeout / shutdown => closes => denied
                w.ShowDialog();
                return w.Decision;
            }).Task;
    }
}
