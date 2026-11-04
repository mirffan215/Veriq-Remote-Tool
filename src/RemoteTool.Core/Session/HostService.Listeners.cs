using System.Net;
using System.Net.Sockets;
using RemoteTool.Core.Relay;

namespace RemoteTool.Core.Session;

public sealed partial class HostService
{
    private TcpListener? _listener;
    private CancellationTokenSource? _listenerCts;
    private RelayRegistration? _relay;

    public bool DirectListening => _listener is not null;
    public RelayStatus RelayStatus => _relay?.Status ?? RelayStatus.Disabled;
    public event Action<RelayStatus>? RelayStatusChanged;

    /// <summary>Mode A. Off by default; the user enables it explicitly.</summary>
    public void StartDirectListener(int port)
    {
        StopDirectListener();
        // Dual-stack where the OS supports IPv6, plain IPv4 otherwise (e.g. IPv6 disabled by policy).
        var l = Socket.OSSupportsIPv6 ? new TcpListener(IPAddress.IPv6Any, port) { Server = { DualMode = true } } : new TcpListener(IPAddress.Any, port);
        l.Start(8);
        _listener = l;
        var cts = _listenerCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        _audit.Write("direct_listener_started", ("port", port));
        _ = AcceptLoopAsync(l, cts.Token);
    }

    public void StopDirectListener()
    {
        if (_listener is null) return;
        _listenerCts?.Cancel();
        _listener.Stop();
        _listener = null;
        _audit.Write("direct_listener_stopped");
    }

    private async Task AcceptLoopAsync(TcpListener l, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient c;
            try { c = await l.AcceptTcpClientAsync(ct).ConfigureAwait(false); }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException) { return; }
            c.NoDelay = true;
            var ip = (c.Client.RemoteEndPoint as IPEndPoint)?.Address;
            if (ip is { IsIPv4MappedToIPv6: true }) ip = ip.MapToIPv4();
            var origin = new PeerOrigin("ip:" + ip, ip?.ToString() ?? "unknown", false, ip);
            _ = Task.Run(() => HandleConnectionAsync(c.GetStream(), origin, ct), ct);
        }
    }

    /// <summary>Mode B: keep this host's ID registered with the relay (outbound only).</summary>
    public void StartRelay(RelayEndpoint endpoint, IIdProvider ids, RelayRegistrationOptions? options = null)
    {
        _ = StopRelayAsync();
        var reg = new RelayRegistration(endpoint, ids, async (stream, viewerAddr, ct) =>
        {
            var origin = new PeerOrigin("relay:" + viewerAddr, viewerAddr + " (via relay)", true, null);
            await HandleConnectionAsync(stream, origin, ct).ConfigureAwait(false);
        }, _audit, options);
        reg.StatusChanged += s => RelayStatusChanged?.Invoke(s);
        _relay = reg;
        reg.Start();
    }

    public async Task StopRelayAsync()
    {
        var r = Interlocked.Exchange(ref _relay, null);
        if (r is null) return;
        await r.DisposeAsync().ConfigureAwait(false);
        RelayStatusChanged?.Invoke(RelayStatus.Disabled);
    }

    private async Task StopListenersAsync()
    {
        StopDirectListener();
        await StopRelayAsync().ConfigureAwait(false);
    }
}
