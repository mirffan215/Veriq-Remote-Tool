using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Lan;

/// <summary>What a visible PC tells its neighbours. Deliberately minimal: no addresses, user names, OS or secrets.</summary>
public sealed record LanAnnouncement(string Id, string Name, int Port);

public sealed record LanHost(string Id, string Name, IPAddress Address, int Port)
{
    public string Endpoint => Address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{Address}]:{Port}" : $"{Address}:{Port}";
}

/// <summary>
/// Wire format of LAN discovery (UDP). The probe is padded to at least <see cref="MinProbeSize"/> bytes and a reply never exceeds that size, so
/// the responder can never amplify traffic towards a spoofed source. Replies are unauthenticated HINTS: authentication is always the password handshake.
/// </summary>
public static class LanProtocol
{
    public const int Port = 21119;
    public const int MinProbeSize = 128, MaxProbeSize = 512, NonceLength = 16;
    private static readonly byte[] ProbeMagic = "RTDISC1"u8.ToArray();
    private static readonly byte[] ReplyMagic = "RTDISR1"u8.ToArray();

    public static byte[] BuildProbe(byte[] nonce)
    {
        var p = new byte[MinProbeSize];
        ProbeMagic.CopyTo(p, 0);
        nonce.CopyTo(p, ProbeMagic.Length);
        return p;
    }

    public static bool TryParseProbe(ReadOnlySpan<byte> d, out byte[] nonce)
    {
        nonce = Array.Empty<byte>();
        if (d.Length < MinProbeSize || d.Length > MaxProbeSize || !d[..ProbeMagic.Length].SequenceEqual(ProbeMagic)) return false;
        nonce = d.Slice(ProbeMagic.Length, NonceLength).ToArray();
        return true;
    }

    public static byte[] BuildReply(byte[] nonce, LanAnnouncement a)
    {
        var name = NameSanitizer.Clean(a.Name, "PC");
        if (name.Length > 24) name = name[..24];
        byte[] reply;
        do
        {
            reply = new ProtoWriter().Fixed(ReplyMagic).Fixed(nonce).U16((ushort)a.Port).Str(a.Id).Str(name).ToArray();
            if (reply.Length > MinProbeSize && name.Length > 1) name = name[..^1];
        } while (reply.Length > MinProbeSize && name.Length > 1);
        return reply;
    }

    public static bool TryParseReply(ReadOnlySpan<byte> d, byte[] expectedNonce, out LanAnnouncement announcement)
    {
        announcement = null!;
        if (d.Length is < 30 or > MinProbeSize || !d[..ReplyMagic.Length].SequenceEqual(ReplyMagic)) return false;
        try
        {
            var r = new ProtoReader(d.ToArray());
            r.Fixed(ReplyMagic.Length);
            var nonce = r.Fixed(NonceLength);
            if (!CryptographicOperations.FixedTimeEquals(nonce, expectedNonce)) return false;   // not an answer to OUR probe
            var port = r.U16();
            var id = r.Str(ConnectionId.MaxLength);
            var name = r.Str(ProtocolConstants.MaxNameChars);
            r.EnsureEnd();
            if (port == 0 || !ConnectionId.IsValid(id)) return false;
            announcement = new LanAnnouncement(id, name, port);
            return true;
        }
        catch (ProtocolException) { return false; }
    }
}

/// <summary>Answers discovery probes while (and only while) the owner has made this PC visible. Never sends unsolicited traffic.</summary>
public sealed class LanResponder : IDisposable
{
    private readonly Func<LanAnnouncement?> _announce;
    private readonly IAuditLog _audit;
    private readonly TimeProvider _time;
    private readonly UdpClient _udp;
    private readonly CancellationTokenSource _cts = new();
    private readonly Dictionary<IPAddress, Queue<DateTimeOffset>> _hits = new();
    private readonly Queue<DateTimeOffset> _global = new();
    private Task? _loop;

    /// <summary>Replies per source per 10 s / total per 10 s.</summary>
    public const int PerSourceLimit = 5, GlobalLimit = 60;
    public int Port { get; }

    public LanResponder(Func<LanAnnouncement?> announce, int port = LanProtocol.Port, IPAddress? bindTo = null, IAuditLog? audit = null, TimeProvider? time = null)
    {
        _announce = announce;
        _audit = audit ?? NullAuditLog.Instance;
        _time = time ?? TimeProvider.System;
        _udp = new UdpClient(new IPEndPoint(bindTo ?? IPAddress.Any, port));   // exclusive bind: no other process may share the port
        Port = ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;
    }

    public void Start() => _loop ??= Task.Run(LoopAsync);

    private bool Allow(IPAddress src)
    {
        var now = _time.GetUtcNow();
        void Trim(Queue<DateTimeOffset> q) { while (q.Count > 0 && now - q.Peek() > TimeSpan.FromSeconds(10)) q.Dequeue(); }
        Trim(_global);
        if (_hits.Count > 512) _hits.Clear();
        if (!_hits.TryGetValue(src, out var q)) _hits[src] = q = new Queue<DateTimeOffset>();
        Trim(q);
        if (q.Count >= PerSourceLimit || _global.Count >= GlobalLimit) return false;
        q.Enqueue(now); _global.Enqueue(now);
        return true;
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            UdpReceiveResult r;
            try { r = await _udp.ReceiveAsync(_cts.Token).ConfigureAwait(false); }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException) { return; }
            catch (SocketException) { continue; }   // e.g. ICMP port-unreachable surfaced on Windows: keep serving
            try
            {
                if (!LanProtocol.TryParseProbe(r.Buffer, out var nonce)) continue;
                var a = _announce();
                if (a is null) continue;                                          // not visible: stay silent
                if (!Allow(r.RemoteEndPoint.Address)) { _audit.Write("lan_probe_throttled", ("source", r.RemoteEndPoint.Address.ToString())); continue; }
                var reply = LanProtocol.BuildReply(nonce, a);
                await _udp.SendAsync(reply, reply.Length, r.RemoteEndPoint).ConfigureAwait(false);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException) { }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _udp.Dispose();
    }
}

public static class LanDiscovery
{
    /// <summary>Directed-broadcast address of a subnet, e.g. 192.168.1.20/255.255.255.0 -> 192.168.1.255.</summary>
    public static IPAddress BroadcastOf(IPAddress ip, IPAddress mask)
    {
        var a = ip.GetAddressBytes(); var m = mask.GetAddressBytes();
        var b = new byte[4];
        for (var i = 0; i < 4; i++) b[i] = (byte)(a[i] | ~m[i]);
        return new IPAddress(b);
    }

    public static IReadOnlyList<IPEndPoint> DefaultTargets(int port)
    {
        var set = new HashSet<IPEndPoint> { new(IPAddress.Broadcast, port) };
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && ua.IPv4Mask is not null)
                        set.Add(new IPEndPoint(BroadcastOf(ua.Address, ua.IPv4Mask), port));
            }
        }
        catch (NetworkInformationException) { }
        return set.ToList();
    }

    /// <summary>Broadcasts a probe and collects the answers for <paramref name="timeout"/>. Probes are repeated once because UDP may drop them.</summary>
    public static async Task<IReadOnlyList<LanHost>> DiscoverAsync(TimeSpan timeout, CancellationToken ct, int port = LanProtocol.Port,
        IReadOnlyList<IPEndPoint>? targets = null, int maxResults = 64)
    {
        targets ??= DefaultTargets(port);
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0)) { EnableBroadcast = true };
        var nonce = RandomNumberGenerator.GetBytes(LanProtocol.NonceLength);
        var probe = LanProtocol.BuildProbe(nonce);
        var found = new Dictionary<(string, IPAddress), LanHost>();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        async Task SendAll()
        {
            foreach (var t in targets)
                try { await udp.SendAsync(probe, probe.Length, t).ConfigureAwait(false); } catch (SocketException) { }
        }
        await SendAll().ConfigureAwait(false);
        var resend = Task.Run(async () => { try { await Task.Delay(timeout / 3, cts.Token); await SendAll(); } catch (OperationCanceledException) { } }, cts.Token);
        try
        {
            while (found.Count < maxResults)
            {
                var r = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                if (!LanProtocol.TryParseReply(r.Buffer, nonce, out var a)) continue;
                var addr = r.RemoteEndPoint.Address;
                found[(a.Id, addr)] = new LanHost(a.Id, NameSanitizer.Clean(a.Name, "PC"), addr, a.Port);
            }
        }
        catch (OperationCanceledException) { }
        catch (SocketException) { }
        try { await resend.ConfigureAwait(false); } catch (OperationCanceledException) { }
        return found.Values.OrderBy(h => h.Name, StringComparer.CurrentCultureIgnoreCase).ThenBy(h => h.Id).ToList();
    }

    /// <summary>Looks for one specific code on the local network. Returns null if nobody answers in time.</summary>
    public static async Task<LanHost?> FindAsync(string id, TimeSpan timeout, CancellationToken ct, int port = LanProtocol.Port, IReadOnlyList<IPEndPoint>? targets = null)
        => (await DiscoverAsync(timeout, ct, port, targets).ConfigureAwait(false)).FirstOrDefault(h => h.Id == id);
}
