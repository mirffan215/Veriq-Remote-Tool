using System.Text;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;
using RemoteTool.Core.Tests;

namespace RemoteTool.Relay.Tests;

public class LimiterTests
{
    private sealed class T : TimeProvider { public DateTimeOffset Now = DateTimeOffset.UnixEpoch; public override DateTimeOffset GetUtcNow() => Now; }

    [Fact]
    public void SlidingWindowLimits()
    {
        var t = new T();
        var l = new SlidingWindowLimiter(3, TimeSpan.FromMinutes(1), t);
        Assert.True(l.TryHit("ip")); Assert.True(l.TryHit("ip")); Assert.True(l.TryHit("ip"));
        Assert.False(l.TryHit("ip"));
        Assert.True(l.TryHit("other"));
        t.Now += TimeSpan.FromSeconds(61);
        Assert.True(l.TryHit("ip"));
    }
}

public class RelayTests
{
    private static Task<(HostService host, RelayRegistration reg, FixedId ids, ListAudit audit, FakeInjector inj)> StartHost(RelayRig rig, string id, string? key = null, string name = "HOSTMARKER-PC")
    {
        var inj = new FakeInjector();
        var audit = new ListAudit();
        var host = new HostService(() => new FakeProducer(), () => inj, new FakeConsent(), audit, new HostPolicy(name));
        var ids = new FixedId(id);
        host.StartRelay(rig.Endpoint(key ?? RelayRig.Key), ids, new RelayRegistrationOptions(TimeSpan.FromMilliseconds(100), 2));
        return Task.FromResult<(HostService, RelayRegistration, FixedId, ListAudit, FakeInjector)>((host, null!, ids, audit, inj));
    }

    [Fact]
    public async Task ViewerReachesHostByIdThroughRelay_EndToEnd_AndRelayCarriesOnlyCiphertext()
    {
        await using var rig = await RelayRig.StartAsync();
        var (host, _, ids, _, inj) = await StartHost(rig, "482913756");
        await using var _h = host;
        await RelayRig.WaitFor(() => host.RelayStatus == RelayStatus.Online);
        Assert.Equal(1, rig.Engine.RegisteredHosts);

        var stream = await RelayClient.ConnectToHostAsync(rig.Endpoint(), "482913756", default);
        const string viewerName = "VIEWERMARKER-ALICE";
        var password = host.Password;
        await using var v = await ViewerSession.ConnectAsync(stream, viewerName, password, new ListAudit(), Permissions.All, default);

        var got = new TaskCompletionSource<FrameUpdateMessage>();
        v.FrameReceived += f => got.TrySetResult(f);
        v.Start();
        var frame = await got.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(64, frame.Width);
        Assert.Equal("HOSTMARKER-PC", v.HostName);

        await v.SendKeyAsync(new KeyEventMessage(66, false, false));
        await RelayRig.WaitFor(() => inj.Events.Contains("key:66:down"));
        Assert.Equal(1, rig.Engine.ActiveSessions);

        // The relay forwarded bytes, but none of the plaintext identifiers appear in them.
        var seen = rig.Observer.Snapshot();
        Assert.True(seen.Length > 1000, "relay should have carried the TLS handshake and frames");
        foreach (var secret in new[] { viewerName, "HOSTMARKER-PC", password, "RemoteTool/1" })
            Assert.False(IndexOf(seen, Encoding.UTF8.GetBytes(secret)) >= 0, $"relay saw plaintext '{secret}'");
    }

    [Fact]
    public async Task UnknownAndOfflineIdsGetTheSameGenericAnswer()
    {
        await using var rig = await RelayRig.StartAsync();
        var e1 = await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(rig.Endpoint(), "111111111", default));
        var e2 = await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(rig.Endpoint(), "999999999", default));
        Assert.Equal(ConnectFailure.NotFound, e1.Failure);
        Assert.Equal(e1.Message, e2.Message);
    }

    [Fact]
    public async Task WrongAccessKeyIsRefused()
    {
        await using var rig = await RelayRig.StartAsync();
        var (host, _, _, _, _) = await StartHost(rig, "555555555");
        await using var _h = host;
        await RelayRig.WaitFor(() => host.RelayStatus == RelayStatus.Online);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(rig.Endpoint("wrong-key"), "555555555", default));
        Assert.Equal(ConnectFailure.NotFound, e.Failure);

        var (badHost, _, _, _, _) = await StartHost(rig, "666666666", key: "wrong-key");
        await using var _b = badHost;
        await RelayRig.WaitFor(() => badHost.RelayStatus == RelayStatus.AccessDenied);
        Assert.Equal(1, rig.Engine.RegisteredHosts);
    }

    [Fact]
    public async Task RelayCertificatePinMismatchIsRejected()
    {
        await using var rig = await RelayRig.StartAsync();
        var bad = rig.Endpoint(fp: new string('A', 64));
        await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(bad, "123456789", default));
    }

    [Fact]
    public async Task DuplicateIdOnAnotherLiveHostForcesRegeneration()
    {
        await using var rig = await RelayRig.StartAsync();
        var (first, _, ids1, _, _) = await StartHost(rig, "777000111");
        await using var _f = first;
        await RelayRig.WaitFor(() => first.RelayStatus == RelayStatus.Online);

        var (copy, _, ids2, audit2, _) = await StartHost(rig, "777000111"); // e.g. copied exe + settings file
        await using var _c = copy;
        await RelayRig.WaitFor(() => ids2.Regenerations == 1);
        Assert.NotEqual("777000111", ids2.Id);
        await RelayRig.WaitFor(() => copy.RelayStatus == RelayStatus.Online);
        Assert.Equal(0, ids1.Regenerations);
        Assert.Equal(2, rig.Engine.RegisteredHosts);
        Assert.True(audit2.Has("id_regenerated"));
    }

    [Fact]
    public async Task HostGoesOfflineWhenItDisconnects()
    {
        await using var rig = await RelayRig.StartAsync();
        var (host, _, _, _, _) = await StartHost(rig, "321654987");
        await RelayRig.WaitFor(() => rig.Engine.RegisteredHosts == 1);
        await host.DisposeAsync();
        await RelayRig.WaitFor(() => rig.Engine.RegisteredHosts == 0);
        await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(rig.Endpoint(), "321654987", default));
    }

    [Fact]
    public async Task FailedLookupsAreRateLimitedPerIp_EvenForValidIds()
    {
        await using var rig = await RelayRig.StartAsync(o => o.FailedLookupsPerMinutePerIp = 3);
        var (host, _, _, _, _) = await StartHost(rig, "246813579");
        await using var _h = host;
        await RelayRig.WaitFor(() => host.RelayStatus == RelayStatus.Online);
        for (var i = 0; i < 3; i++)
            await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(rig.Endpoint(), "100000000", default));
        // Now the source is throttled: a lookup of a perfectly valid, online ID gets the same generic NotFound.
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(rig.Endpoint(), "246813579", default));
        Assert.Equal(ConnectFailure.NotFound, e.Failure);
    }

    private static int IndexOf(byte[] hay, byte[] needle)
        => hay.AsSpan().IndexOf(needle);
}
