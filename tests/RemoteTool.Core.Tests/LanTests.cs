using System.Net;
using System.Net.Sockets;
using RemoteTool.Core.Lan;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

public class LanDiscoveryTests
{
    private static readonly IPEndPoint Loop = new(IPAddress.Loopback, 0);
    private static LanAnnouncement Ann(string name = "RECEPTION-PC", int port = 21118) => new("482913756012", name, port);
    private static IReadOnlyList<IPEndPoint> To(LanResponder r) => new[] { new IPEndPoint(IPAddress.Loopback, r.Port) };

    [Fact]
    public async Task VisiblePcIsFoundWithItsCodeNameAndPort()
    {
        using var r = new LanResponder(() => Ann(), 0, IPAddress.Loopback); r.Start();
        var hosts = await LanDiscovery.DiscoverAsync(TimeSpan.FromMilliseconds(700), default, r.Port, To(r));
        var h = Assert.Single(hosts);
        Assert.Equal(("482913756012", "RECEPTION-PC", 21118), (h.Id, h.Name, h.Port));
        Assert.Equal("127.0.0.1:21118", h.Endpoint);
    }

    [Fact]
    public async Task InvisiblePcStaysSilent_NothingIsRevealed()
    {
        using var r = new LanResponder(() => null, 0, IPAddress.Loopback); r.Start();
        Assert.Empty(await LanDiscovery.DiscoverAsync(TimeSpan.FromMilliseconds(500), default, r.Port, To(r)));
    }

    [Fact]
    public async Task FindAsyncResolvesACodeToAnAddress()
    {
        using var r = new LanResponder(() => Ann(), 0, IPAddress.Loopback); r.Start();
        var hit = await LanDiscovery.FindAsync("482913756012", TimeSpan.FromMilliseconds(700), default, r.Port, To(r));
        Assert.NotNull(hit);
        Assert.Null(await LanDiscovery.FindAsync("999999999999", TimeSpan.FromMilliseconds(400), default, r.Port, To(r)));
    }

    [Fact]
    public async Task ResponderNeverAmplifies_RepliesAreNeverLargerThanTheProbe_AndShortOrForeignPacketsAreIgnored()
    {
        using var r = new LanResponder(() => Ann(new string('ش', 60)), 0, IPAddress.Loopback); r.Start();   // long non-Latin name = worst case for size
        using var c = new UdpClient(Loop);
        var nonce = new byte[LanProtocol.NonceLength];

        async Task<byte[]?> Ask(byte[] packet)
        {
            await c.SendAsync(packet, packet.Length, new IPEndPoint(IPAddress.Loopback, r.Port));
            using var cts = new CancellationTokenSource(400);
            try { return (await c.ReceiveAsync(cts.Token)).Buffer; } catch (OperationCanceledException) { return null; }
        }

        var probe = LanProtocol.BuildProbe(nonce);
        var reply = await Ask(probe);
        Assert.NotNull(reply);
        Assert.True(reply!.Length <= probe.Length, $"reply {reply.Length} > probe {probe.Length}");

        Assert.Null(await Ask(probe[..64]));                                   // too small: would allow amplification
        var bad = (byte[])probe.Clone(); bad[0] ^= 0xFF;
        Assert.Null(await Ask(bad));                                           // wrong magic
        Assert.Null(await Ask(new byte[4096]));                                // oversized
        Assert.Null(await Ask(System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\n\r\n")));
    }

    [Fact]
    public async Task ProbesAreRateLimitedPerSource()
    {
        using var r = new LanResponder(() => Ann(), 0, IPAddress.Loopback); r.Start();
        using var c = new UdpClient(Loop);
        var probe = LanProtocol.BuildProbe(new byte[LanProtocol.NonceLength]);
        for (var i = 0; i < 40; i++) await c.SendAsync(probe, probe.Length, new IPEndPoint(IPAddress.Loopback, r.Port));
        var replies = 0;
        while (true)
        {
            using var cts = new CancellationTokenSource(500);
            try { await c.ReceiveAsync(cts.Token); replies++; } catch (OperationCanceledException) { break; }
        }
        Assert.InRange(replies, 1, LanResponder.PerSourceLimit);
    }

    [Fact]
    public async Task ForgedAndMalformedRepliesAreIgnoredByTheDiscoverer()
    {
        // A hostile neighbour answers every probe with garbage, with someone else's nonce, with an invalid code, with port 0 and with an oversized packet.
        using var evil = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var evilPort = ((IPEndPoint)evil.Client.LocalEndPoint!).Port;
        var stop = new CancellationTokenSource();
        _ = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                UdpReceiveResult q;
                try { q = await evil.ReceiveAsync(stop.Token); } catch { return; }
                if (!LanProtocol.TryParseProbe(q.Buffer, out var nonce)) continue;
                var other = (byte[])nonce.Clone(); other[0] ^= 1;
                var packets = new[]
                {
                    LanProtocol.BuildReply(other, Ann()),                                   // answer to a different probe (replay)
                    LanProtocol.BuildReply(nonce, new LanAnnouncement("123", "short", 5)),  // invalid code
                    LanProtocol.BuildReply(nonce, new LanAnnouncement("482913756012", "p0", 0)), // port 0
                    new byte[2000], new byte[] { 1, 2, 3 },
                };
                foreach (var p in packets) await evil.SendAsync(p, p.Length, q.RemoteEndPoint);
            }
        });
        var hosts = await LanDiscovery.DiscoverAsync(TimeSpan.FromMilliseconds(600), default, evilPort, new[] { new IPEndPoint(IPAddress.Loopback, evilPort) });
        stop.Cancel();
        Assert.Empty(hosts);
    }

    [Fact]
    public void ReplyParserSurvivesRandomBytes()
    {
        var rng = new Random(5); var nonce = new byte[LanProtocol.NonceLength];
        for (var i = 0; i < 30000; i++)
        {
            var d = new byte[rng.Next(0, 200)]; rng.NextBytes(d);
            LanProtocol.TryParseReply(d, nonce, out _);       // must never throw
            LanProtocol.TryParseProbe(d, out _);
        }
    }

    [Fact]
    public void NamesAreSanitizedAndTruncatedInsideTheSizeBudget()
    {
        var reply = LanProtocol.BuildReply(new byte[16], new LanAnnouncement("482913756012", "evil\u0007‮name" + new string('x', 200), 1));
        Assert.True(reply.Length <= LanProtocol.MinProbeSize);
        Assert.True(LanProtocol.TryParseReply(reply, new byte[16], out var a));
        Assert.DoesNotContain(a.Name, c => char.IsControl(c));
    }

    [Theory]
    [InlineData("192.168.1.20", "255.255.255.0", "192.168.1.255")]
    [InlineData("10.4.7.9", "255.255.0.0", "10.4.255.255")]
    [InlineData("172.16.5.130", "255.255.255.128", "172.16.5.255")]
    public void BroadcastAddressIsComputedFromTheSubnet(string ip, string mask, string expected)
        => Assert.Equal(IPAddress.Parse(expected), LanDiscovery.BroadcastOf(IPAddress.Parse(ip), IPAddress.Parse(mask)));

    [Fact]
    public async Task EndToEnd_CodeResolvedOnTheLan_ThenPasswordHandshakeAndConsent_NoRelayInvolved()
    {
        var consent = new FakeConsent();
        await using var host = new HostService(() => new FakeProducer(), () => new FakeInjector(), consent, new ListAudit(), new HostPolicy("LAN-PC"));
        var probe = new TcpListener(IPAddress.Loopback, 0); probe.Start(); var tcpPort = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
        host.StartDirectListener(tcpPort);
        using var r = new LanResponder(() => new LanAnnouncement("482913756012", "LAN-PC", tcpPort), 0, IPAddress.Loopback); r.Start();

        var found = await LanDiscovery.FindAsync("482913756012", TimeSpan.FromMilliseconds(700), default, r.Port, To(r));
        Assert.NotNull(found);
        var c = new TcpClient(); await c.ConnectAsync(found!.Address, found.Port);
        await using var v = await ViewerSession.ConnectAsync(c.GetStream(), "alice", host.Password, new ListAudit(), Permissions.All, default);
        Assert.Equal("LAN-PC", v.HostName);
        Assert.Equal(1, consent.Calls);                                         // discovery did NOT bypass consent
    }

    [Fact]
    public async Task DiscoveryHintCannotAuthenticateAnything_WrongPasswordStillFails()
    {
        await using var host = new HostService(() => new FakeProducer(), () => new FakeInjector(), new FakeConsent(), new ListAudit(), new HostPolicy("LAN-PC"));
        var probe = new TcpListener(IPAddress.Loopback, 0); probe.Start(); var tcpPort = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
        host.StartDirectListener(tcpPort);
        var c = new TcpClient(); await c.ConnectAsync(IPAddress.Loopback, tcpPort);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(c.GetStream(), "alice", "WRONGPW2", new ListAudit(), Permissions.All, default));
        Assert.Equal(ConnectFailure.BadPassword, e.Failure);
    }
}
