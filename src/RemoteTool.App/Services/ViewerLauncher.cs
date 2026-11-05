using System.Net.Sockets;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Lan;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;
using RemoteTool.Video;

namespace RemoteTool.App.Services;

/// <summary>Everything a viewer window needs besides the session itself (clipboard, file prompt, re-dial for auto-reconnect).</summary>
public sealed record ViewerContext(string ViewerName, IAuditLog Audit, Func<CancellationToken, Task<Stream>> Redial,
    Func<IClipboardAccess> ClipboardFactory, IFileTransferPrompt Prompt, FileTransferOptions FileOptions, Func<IH264Decoder?> DecoderFactory);

/// <summary>Request = just ask (the other person clicks Accept). Password = the other person gave you a password: try it as their access password, then as their one-time password.</summary>
public enum ConnectMode { Request, Password }

public sealed class ViewerLauncher
{
    private readonly SettingsStore _store;
    private readonly ISecretProtector _protector;
    private readonly IAuditLog _audit;
    private readonly IFileTransferPrompt _prompt;
    private readonly string _receiveDir;

    public ViewerLauncher(SettingsStore store, ISecretProtector protector, IAuditLog audit, IFileTransferPrompt prompt, string receiveDir)
    {
        _store = store;
        _protector = protector;
        _audit = audit;
        _prompt = prompt;
        _receiveDir = receiveDir;
    }

    /// <summary>Opens a raw transport to the target (relay pairing or direct TCP). Used for first connect and for reconnects.</summary>
    private static bool Dispose(IDisposable d) { d.Dispose(); return true; }

    public async Task<Stream> DialAsync(ConnectTarget target, CancellationToken ct)
    {
        var s = _store.Current;
        switch (target)
        {
            case ConnectTarget.ById byId:
            {
                var hasRelay = RelayEndpoint.TryParseList(s.RelayAddress, "", "", out _);
                // Local network first when asked to, or when there is no relay at all (pure LAN deployment).
                if (s.LanFirst || !hasRelay)
                {
                    var lan = await LanDiscovery.FindAsync(byId.Id, TimeSpan.FromMilliseconds(1500), ct);
                    if (lan is not null) { _audit.Write("lan_resolved", ("address", lan.Address.ToString())); return await DialAsync(new ConnectTarget.Direct(lan.Address.ToString(), lan.Port), ct); }
                    if (!hasRelay) throw new ConnectFailedException(ConnectFailure.NotFound, Localization.Loc.T("Err_NoRelayNoLan"));
                }
                var key = string.IsNullOrEmpty(s.RelayAccessKeyProtected) ? "" : _protector.Unprotect(s.RelayAccessKeyProtected);
                if (!RelayEndpoint.TryParseList(s.RelayAddress, key, s.RelayFingerprint, out var relays))
                    throw new ConnectFailedException(ConnectFailure.Network, Localization.Loc.T("Err_NoRelay"));
                return await RelayClient.ConnectToHostAsync(relays, byId.Id, ct);
            }
            case ConnectTarget.Direct d:
            {
                var tcp = new TcpClient { NoDelay = true };
                try
                {
                    using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    c.CancelAfter(TimeSpan.FromSeconds(15));
                    await tcp.ConnectAsync(d.Host, d.Port, c.Token);
                    return tcp.GetStream();
                }
                catch (Exception e) when (e is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
                {
                    tcp.Dispose();
                    throw new ConnectFailedException(ConnectFailure.Network, $"Cannot reach {d.Host}:{d.Port} ({(e is SocketException se ? se.SocketErrorCode.ToString() : "timed out after 15 s")}). Check the address, that RemoteTool is running there, and the firewall.", e);
                }
            }
            default: throw new ArgumentException("unknown target");
        }
    }

    /// <summary>"Find PCs on this network": every visible RemoteTool PC on the local subnet(s).</summary>
    public Task<IReadOnlyList<LanHost>> FindLanHostsAsync(CancellationToken ct) => LanDiscovery.DiscoverAsync(TimeSpan.FromMilliseconds(1500), ct);

    public async Task<(ViewerSession Session, ViewerContext Context)> ConnectAsync(ConnectTarget target, string secret, ConnectMode mode, Action<string>? onSecurityCode, CancellationToken ct)
    {
        var s = _store.Current;
        _audit.Write("connection_attempt", ("target", target switch { ConnectTarget.ById b => b.Id, ConnectTarget.Direct d => $"{d.Host}:{d.Port}", _ => "?" }), ("mode", mode));
        // Offer H.264 only if this PC can decode it; the host decides and can still fall back to tiles at any time.
        var h264 = s.EnableH264 && Video.H264Support.CreateDecoder() is { } probe ? Dispose(probe) : false;
        var codecs = h264 ? VideoCodecs.TileJpeg | VideoCodecs.H264 : VideoCodecs.TileJpeg;

        async Task<ViewerSession> Attempt(bool consentOnly, bool permanent)
        {
            var transport = await DialAsync(target, ct);
            return await ViewerSession.ConnectAsync(transport, s.DisplayName, secret, _audit, Permissions.All, ct, permanent: permanent, codecs: codecs,
                consentOnly: consentOnly, onSecurityCode: onSecurityCode);
        }

        ViewerSession session;
        if (mode == ConnectMode.Request) session = await Attempt(consentOnly: true, permanent: false);
        else
        {
            try { session = await Attempt(consentOnly: false, permanent: true); }                                  // their ACCESS password
            catch (ConnectFailedException e) when (e.Failure == ConnectFailure.BadPassword) { session = await Attempt(consentOnly: false, permanent: false); }   // their one-time password
        }
        var ctx = new ViewerContext(s.DisplayName, _audit, c => DialAsync(target, c), () => new WindowsClipboard(), _prompt,
            new FileTransferOptions(_receiveDir, Math.Max(1, s.MaxFileTransferMb) * 1024L * 1024), () => Video.H264Support.CreateDecoder());
        return (session, ctx);
    }
}
