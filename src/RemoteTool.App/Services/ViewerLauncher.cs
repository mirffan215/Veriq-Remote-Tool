using System.Net.Sockets;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;

namespace RemoteTool.App.Services;

public sealed class ViewerLauncher
{
    private readonly SettingsStore _store;
    private readonly ISecretProtector _protector;
    private readonly IAuditLog _audit;

    public ViewerLauncher(SettingsStore store, ISecretProtector protector, IAuditLog audit)
    {
        _store = store;
        _protector = protector;
        _audit = audit;
    }

    public async Task<ViewerSession> ConnectAsync(ConnectTarget target, string password, CancellationToken ct)
    {
        var s = _store.Current;
        _audit.Write("connection_attempt", ("target", target switch { ConnectTarget.ById b => b.Id, ConnectTarget.Direct d => $"{d.Host}:{d.Port}", _ => "?" }));
        Stream transport;
        switch (target)
        {
            case ConnectTarget.ById byId:
            {
                var key = string.IsNullOrEmpty(s.RelayAccessKeyProtected) ? "" : _protector.Unprotect(s.RelayAccessKeyProtected);
                if (!RelayEndpoint.TryParse(s.RelayAddress, key, s.RelayFingerprint, out var ep))
                    throw new ConnectFailedException(ConnectFailure.Network, Localization.Loc.T("Err_NoRelay"));
                transport = await RelayClient.ConnectToHostAsync(ep!, byId.Id, ct);
                break;
            }
            case ConnectTarget.Direct d:
            {
                var tcp = new TcpClient { NoDelay = true };
                try
                {
                    using var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    c.CancelAfter(TimeSpan.FromSeconds(15));
                    await tcp.ConnectAsync(d.Host, d.Port, c.Token);
                    transport = tcp.GetStream();
                }
                catch (Exception e) when (e is SocketException or OperationCanceledException && !ct.IsCancellationRequested)
                {
                    tcp.Dispose();
                    throw new ConnectFailedException(ConnectFailure.Network, $"Cannot reach {d.Host}:{d.Port}.", e);
                }
                break;
            }
            default: throw new ArgumentException("unknown target");
        }
        return await ViewerSession.ConnectAsync(transport, s.DisplayName, password, _audit, Permissions.All, ct);
    }
}
