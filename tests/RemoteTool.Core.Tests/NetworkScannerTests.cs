using System.Net;
using System.Net.Sockets;
using RemoteTool.Core.Lan;

namespace RemoteTool.Core.Tests;

public class NetworkScannerTests
{
    private static Task<IPAddress[]> NoDns(string n, CancellationToken ct) => Task.FromResult(n switch
    {
        "pc01.corp.local" => new[] { IPAddress.Parse("10.10.5.34") },
        "public.example" => new[] { IPAddress.Parse("8.8.8.8") },
        _ => throw new SocketException(11001),
    });

    [Fact]
    public async Task ParsesCidrRangesSingleAddressesAndNames()
    {
        var r = await NetworkScanner.ParseAsync("10.10.5.0/24, 192.168.1.10-192.168.1.12; 172.16.0.5-7 10.0.0.1 pc01.corp.local", NoDns);
        Assert.True(r.Ok, r.Error);
        Assert.Equal(254 + 3 + 3 + 1 /*10.0.0.1*/ + 0 /*pc01 is already inside 10.10.5.0/24*/, r.Addresses.Count);
        Assert.DoesNotContain(IPAddress.Parse("10.10.5.0"), r.Addresses);     // network and broadcast addresses are skipped
        Assert.DoesNotContain(IPAddress.Parse("10.10.5.255"), r.Addresses);
        Assert.Contains(IPAddress.Parse("10.10.5.34"), r.Addresses);
        Assert.Contains(IPAddress.Parse("172.16.0.7"), r.Addresses);
    }

    [Theory]
    [InlineData("8.8.8.8", "not a private")]
    [InlineData("1.2.3.0/24", "not a private")]
    [InlineData("10.0.0.0/8", "too large")]
    [InlineData("10.0.0.0/16", "too large")]
    [InlineData("10.0.0.1-10.0.50.1", "more than")]
    [InlineData("public.example", "not a private")]
    [InlineData("nosuchname.local", "Cannot find")]
    [InlineData("10.0.0.0/33", "not a valid")]
    [InlineData("300.1.1.1", "not a valid")]
    [InlineData("10.0.0.9-10.0.0.1", "ends before")]
    [InlineData("   ", "Nothing to scan")]
    public async Task RefusesPublicHugeAndMalformedTargets(string input, string reason)
    {
        var r = await NetworkScanner.ParseAsync(input, NoDns);
        Assert.False(r.Ok);
        Assert.Contains(reason, r.Error);
        Assert.Empty(r.Addresses);
    }

    [Fact]
    public async Task A20NetworkIsTheLargestAllowed()
    {
        Assert.True((await NetworkScanner.ParseAsync("10.1.16.0/20", NoDns)).Ok);
        Assert.False((await NetworkScanner.ParseAsync("10.1.0.0/19", NoDns)).Ok);
    }

    [Fact]
    public void PrivateRangesAreRecognised()
    {
        foreach (var ok in new[] { "10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.0.1", "127.0.0.1", "169.254.1.1", "100.64.0.1" }) Assert.True(NetworkScanner.IsPrivate(IPAddress.Parse(ok)), ok);
        foreach (var no in new[] { "8.8.8.8", "172.32.0.1", "172.15.0.1", "192.169.0.1", "100.128.0.1", "11.0.0.1" }) Assert.False(NetworkScanner.IsPrivate(IPAddress.Parse(no)), no);
    }

    [Fact]
    public async Task FindsOnlyAddressesWithTheOpenPort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        var hits = new List<ScanHit>(); var gate = new object();
        var targets = new[] { IPAddress.Parse("127.0.0.1"), IPAddress.Parse("127.0.0.2") };   // 127.0.0.2 is also local but nothing listens on it
        ScanProgress? last = null;
        await NetworkScanner.ScanAsync(targets, port, h => { lock (gate) hits.Add(h); }, new Progress<ScanProgress>(p => last = p), resolveNames: false);
        var hit = Assert.Single(hits);
        Assert.Equal("127.0.0.1", hit.Address.ToString());
        Assert.Equal($"127.0.0.1:{port}", hit.Endpoint);
        await Task.Delay(100);
        Assert.Equal(2, last?.Total);
    }

    [Fact]
    public async Task ClosedPortsAreFastAndNothingIsFound()
    {
        var hits = 0;
        var targets = Enumerable.Range(1, 60).Select(i => IPAddress.Parse($"127.0.0.{i}")).ToList();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await NetworkScanner.ScanAsync(targets, 1, _ => Interlocked.Increment(ref hits), resolveNames: false);
        Assert.Equal(0, hits);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15));
    }

    [Fact]
    public async Task ScanCanBeCancelled()
    {
        using var cts = new CancellationTokenSource(); cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => NetworkScanner.ScanAsync(new[] { IPAddress.Loopback }, 1, _ => { }, ct: cts.Token));
    }

    [Fact]
    public void LocalNetworksAreNeverPublicOrHuge()
    {
        foreach (var n in NetworkScanner.LocalNetworks())
        {
            var p = n.Split('/');
            Assert.True(NetworkScanner.IsPrivate(IPAddress.Parse(p[0])));
            Assert.True(int.Parse(p[1]) >= 22);
        }
    }
}
