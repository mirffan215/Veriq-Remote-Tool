using System.Net.Sockets;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Services;

/// <summary>Everything a viewer window needs besides the session itself (clipboard, file prompt, re-dial for auto-reconnect).</summary>
public sealed record ViewerContext(string ViewerName, IAuditLog Audit, Func<CancellationToken, Task<Stream>> Redial,
    Func<IClipboardAccess> ClipboardFactory, IFileTransferPrompt Prompt, FileTransferOptions FileOptions);

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
    public async Task<Stream> DialAsync(ConnectTarget target, CancellationToken ct)
    {
        var s = _store.Current;
        switch (target)
        {
            case ConnectTarget.ById byId:
            {
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
                    throw new ConnectFailedException(ConnectFailure.Network, $"Cannot reach {d.Host}:{d.Port}.", e);
                }
            }
            default: throw new ArgumentException("unknown target");
        }
    }

    public async Task<(ViewerSession Session, ViewerContext Context)> ConnectAsync(ConnectTarget target, string password, CancellationToken ct)
    {
        var s = _store.Current;
        _audit.Write("connection_attempt", ("target", target switch { ConnectTarget.ById b => b.Id, ConnectTarget.Direct d => $"{d.Host}:{d.Port}", _ => "?" }));
        var transport = await DialAsync(target, ct);
        var session = await ViewerSession.ConnectAsync(transport, s.DisplayName, password, _audit, Permissions.All, ct);
        var ctx = new ViewerContext(s.DisplayName, _audit, c => DialAsync(target, c), () => new WindowsClipboard(), _prompt,
            new FileTransferOptions(_receiveDir, Math.Max(1, s.MaxFileTransferMb) * 1024L * 1024));
        return (session, ctx);
    }
}
