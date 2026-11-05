using System.Text.Json;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Lan;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Recording;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Security;
using RemoteTool.Core.Session;
using RemoteTool.Service.Helper;

namespace RemoteTool.Service;

/// <summary>
/// The service's brain, independent of Windows: a headless <see cref="HostService"/> that accepts ONLY the permanent password (and resume tickets),
/// whose screen/input go through the per-session helper. The Windows <c>ServiceBase</c> shell just starts and stops it.
/// </summary>
public sealed class ServiceRuntime : IAsyncDisposable
{
    private readonly ServicePaths _paths;
    private readonly ServiceConfigStore _store;
    private readonly ServiceConfig _cfg;
    private readonly PermanentPasswordStore _permanent;
    private readonly ISecretProtector _protector;
    private readonly IAuditLog _audit;
    private readonly HelperSupervisor _helpers;
    private readonly ISasSender _sas;
    private HostService? _host;
    private LanResponder? _lan;
    private string _relayStatus = "Disabled";

    public ServiceRuntime(ServicePaths paths, ISecretProtector protector, IHelperLauncher launcher, ISasSender sas, IAuditLog? audit = null, TimeSpan? helperRetry = null)
    {
        _paths = paths;
        _protector = protector;
        _sas = sas;
        Directory.CreateDirectory(paths.ServiceDir);
        _store = new ServiceConfigStore(paths.ConfigFile);
        _cfg = _store.Load();
        _permanent = new PermanentPasswordStore(paths.PermanentFile, protector);
        _audit = audit ?? new JsonlAuditLog(paths.LogDir, "service");
        _helpers = new HelperSupervisor(launcher, _audit, helperRetry);
    }

    public HostService Host => _host ?? throw new InvalidOperationException("not started");
    public ServiceConfig Config => _cfg;
    public int? LanPort => _lan?.Port;
    public HelperSupervisor Helpers => _helpers;

    public void Start()
    {
        var unattended = new UnattendedPolicy(() => _cfg, _helpers, _audit);
        ISessionRecorderFactory? recorder = _cfg.RecordSessions ? new SessionRecorderFactory(_paths.RecordingDir, _protector, _cfg.RecordingRetentionDays) : null;
        // The service never accepts click-only requests: it must be reachable only with the permanent password (nobody may be there to click).
        var policy = new HostPolicy(_cfg.DisplayName, ViewOnly: false, AllowClipboard: false, AllowFileTransfer: false, _cfg.IpAllowList.ToArray(), AllowConsentOnly: false);

        _host = new HostService(
            producerFactory: () => new PipeFrameProducer(_helpers.GetChannelAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult()),
            injectorFactory: () => new PipeInputInjector(_helpers.GetChannelAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult(), _sas),
            consent: new DenyAttendedConsent(),
            audit: _audit,
            policy: policy,
            permanentCredential: new GatedCredential(_permanent, () => _cfg.UnattendedEnabled),
            unattended: unattended,
            recorderFactory: recorder,
            oneTimePasswordEnabled: false);

        _helpers.ChannelReady += WireHelperEvents;
        _host.SessionStarted += s => { try { _helpers.Current?.ShowBannerAsync(s.ViewerName, _cfg.RecordSessions).GetAwaiter().GetResult(); } catch (IOException) { } };
        _host.SessionEnded += (_, _) => { try { _helpers.Current?.HideBannerAsync().GetAwaiter().GetResult(); } catch (IOException) { } };
        _host.RelayStatusChanged += s => { _relayStatus = s.ToString(); WriteStatus(); };

        _helpers.Start();
        var key = string.IsNullOrEmpty(_cfg.RelayAccessKeyProtected) ? "" : _protector.Unprotect(_cfg.RelayAccessKeyProtected);
        if (RelayEndpoint.TryParseList(_cfg.RelayAddress, key, _cfg.RelayFingerprint, out var relays))
            _host.StartRelay(relays, new ConfigIdProvider(_store, _cfg));
        if (_cfg.DirectListenerEnabled)
        {
            try { _host.StartDirectListener(_cfg.DirectPort); } catch (Exception e) when (e is System.Net.Sockets.SocketException) { _audit.Write("direct_listener_failed", ("error", e.GetType().Name)); }
        }
        if (_cfg.DirectListenerEnabled && _cfg.LanVisible)
        {
            try
            {
                _lan = new LanResponder(() => new LanAnnouncement(_cfg.Id, _cfg.DisplayName, _cfg.DirectPort), _cfg.LanDiscoveryPort, audit: _audit);
                _lan.Start();
                _audit.Write("lan_visibility_on", ("port", _lan.Port));
            }
            catch (System.Net.Sockets.SocketException e) { _audit.Write("lan_visibility_failed", ("error", e.GetType().Name)); }
        }
        _audit.Write("service_started", ("id", _cfg.Id), ("unattendedEnabled", _cfg.UnattendedEnabled), ("permanentPasswordSet", _permanent.Enabled), ("recording", _cfg.RecordSessions));
        WriteStatus();
    }

    private void WireHelperEvents(HelperChannel ch)
    {
        ch.EmergencyHotkey += () => _host?.DisconnectActive(ByeReason.Emergency);
        ch.BannerDisconnect += () => _host?.DisconnectActive(ByeReason.HostDisconnected);
    }

    /// <summary>Non-sensitive status for the user-mode UI: lets it show "managed by service, ID …".</summary>
    private void WriteStatus()
    {
        try
        {
            Directory.CreateDirectory(_paths.PublicDir);
            var json = JsonSerializer.Serialize(new { id = _cfg.Id, relay = _relayStatus, unattendedEnabled = _cfg.UnattendedEnabled, permanentPasswordSet = _permanent.Enabled, updatedUtc = DateTimeOffset.UtcNow });
            File.WriteAllText(_paths.PublicStatusFile + ".tmp", json);
            File.Move(_paths.PublicStatusFile + ".tmp", _paths.PublicStatusFile, true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
    }

    public void NotifySessionChanged() => _helpers.NotifySessionChanged();

    public async ValueTask DisposeAsync()
    {
        _audit.Write("service_stopping");
        _lan?.Dispose();
        if (_host is not null) await _host.DisposeAsync().ConfigureAwait(false);
        await _helpers.DisposeAsync().ConfigureAwait(false);
    }

    /// <summary>The permanent credential is inert unless the master opt-in switch is on.</summary>
    private sealed class GatedCredential : IPermanentCredential
    {
        private readonly IPermanentCredential _inner;
        private readonly Func<bool> _enabled;
        public GatedCredential(IPermanentCredential inner, Func<bool> enabled) { _inner = inner; _enabled = enabled; }
        public bool Enabled => _enabled() && _inner.Enabled;
        public byte[] Salt => _inner.Salt;
        public byte[] Key => _inner.Key;
    }

    /// <summary>Attended (one-time password) sessions do not exist in service mode.</summary>
    private sealed class DenyAttendedConsent : IConsentProvider
    {
        public Task<ConsentDecision> RequestAsync(ConsentRequestInfo info, CancellationToken ct) => Task.FromResult(new ConsentDecision(false, Permissions.None));
    }
}
