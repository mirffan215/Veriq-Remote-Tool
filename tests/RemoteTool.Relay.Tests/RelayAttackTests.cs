using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using RemoteTool.Core.Config;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;
using RemoteTool.Core.Tests;

namespace RemoteTool.Relay.Tests;

/// <summary>The relay is internet-facing and must be hostile-input-proof. Each test plays the attacker.</summary>
public class RelayAttackTests
{
    private const string IdA = "100200300400", IdB = "500600700800";

    private sealed class Raw : IAsyncDisposable
    {
        public Stream S = null!; public FrameReader R = null!; public FrameWriter W = null!;
        public static async Task<Raw> OpenAsync(RelayRig rig, string? key = null)
        {
            var s = await RelayClient.OpenAsync(rig.Endpoint(key ?? RelayRig.Key), default);
            return new Raw { S = s, R = new FrameReader(s, MessageTypes.IsKnownRelay, 512), W = new FrameWriter(s) };
        }
        public Task Register(string id, byte[]? instance = null, string? key = null)
            => W.WriteAsync(RelayMessageType.Register, new RegisterMessage(key ?? RelayRig.Key, id, instance ?? RandomNumberGenerator.GetBytes(16)).Serialize(), default);
        public async Task<RelayMessageType?> ReadType(int ms = 3000)
        {
            using var c = new CancellationTokenSource(ms);
            try { return (RelayMessageType)(await R.ReadAsync(c.Token)).Type; }
            catch (Exception e) when (e is OperationCanceledException or IOException or EndOfStreamException or ProtocolException) { return null; }
        }
        public async Task<bool> ClosedWithin(int ms)
        {
            using var c = new CancellationTokenSource(ms);
            try { while (true) await R.ReadAsync(c.Token); }
            catch (OperationCanceledException) { return false; }
            catch (Exception e) when (e is IOException or EndOfStreamException or ProtocolException) { return true; }
        }
        public ValueTask DisposeAsync() => S.DisposeAsync();
    }

    private static HostService NewHost(RelayRig rig, string id, string name, out FixedId ids)
    {
        var host = new HostService(() => new FakeProducer(), () => new FakeInjector(), new FakeConsent(), new ListAudit(), new HostPolicy(name));
        ids = new FixedId(id);
        host.StartRelay(rig.Endpoint(), ids, new RelayRegistrationOptions(TimeSpan.FromMilliseconds(100), 2));
        return host;
    }

    [Fact]
    public async Task GuessedPairingTokenIsUseless()
    {
        await using var rig = await RelayRig.StartAsync();
        await using var host = NewHost(rig, IdA, "H", out _);
        await RelayRig.WaitFor(() => host.RelayStatus == RelayStatus.Online);
        for (var i = 0; i < 20; i++)
        {
            await using var a = await Raw.OpenAsync(rig);
            await a.W.WriteAsync(RelayMessageType.Accept, new AcceptMessage(RelayRig.Key, IdA, RandomNumberGenerator.GetBytes(16)).Serialize(), default);
            Assert.True(await a.ClosedWithin(3000));
        }
        Assert.Equal(0, rig.Engine.ActiveSessions);
    }

    [Fact]
    public async Task StolenTokenCannotBeUsedForAnotherId_OnlyTheRealHostCompletesThePairing()
    {
        await using var rig = await RelayRig.StartAsync();
        await using var raw = await Raw.OpenAsync(rig);                       // a hand-driven "host" so we can see the token
        await raw.Register(IdA);
        Assert.Equal(RelayMessageType.Registered, await raw.ReadType());

        var viewer = Task.Run(() => RelayClient.ConnectToHostAsync(rig.Endpoint(), IdA, default));
        var incoming = IncomingMessage.Parse((await raw.R.ReadAsync(default)).Payload);   // the relay tells the host a token

        await using (var thief = await Raw.OpenAsync(rig))                    // attacker who learned the token (e.g. by sniffing a log) but registered/claims ANOTHER id
        {
            await thief.W.WriteAsync(RelayMessageType.Accept, new AcceptMessage(RelayRig.Key, IdB, incoming.Token).Serialize(), default);
            Assert.True(await thief.ClosedWithin(3000));
        }
        Assert.False(viewer.IsCompleted);                                     // viewer is still waiting for the genuine host

        await using var real = await Raw.OpenAsync(rig);
        await real.W.WriteAsync(RelayMessageType.Accept, new AcceptMessage(RelayRig.Key, IdA, incoming.Token).Serialize(), default);
        Assert.Equal(RelayMessageType.Ready, await real.ReadType());
        await using var paired = await viewer.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task SecondRegistrationOfALiveIdWithoutTheInstanceSecretIsRefused_OriginalKeepsWorking()
    {
        await using var rig = await RelayRig.StartAsync();
        await using var host = NewHost(rig, IdA, "REAL-HOST", out _);
        await RelayRig.WaitFor(() => host.RelayStatus == RelayStatus.Online);

        await using var hijacker = await Raw.OpenAsync(rig);                  // knows the access key and the ID, but not the host's 128-bit instance secret
        await hijacker.Register(IdA, RandomNumberGenerator.GetBytes(16));
        Assert.Equal(RelayMessageType.IdTaken, await hijacker.ReadType());

        var stream = await RelayClient.ConnectToHostAsync(rig.Endpoint(), IdA, default);
        await using var v = await ViewerSession.ConnectAsync(stream, "u", host.Password, new ListAudit(), Permissions.All, default);
        Assert.Equal("REAL-HOST", v.HostName);                                // still the real host
    }

    [Fact]
    public async Task RegistrationFloodFromOneAddressIsThrottled()
    {
        await using var rig = await RelayRig.StartAsync(o => o.RegistrationsPerMinutePerIp = 5);
        var results = new List<RelayMessageType?>();
        var keep = new List<Raw>();
        for (var i = 0; i < 9; i++)
        {
            var r = await Raw.OpenAsync(rig); keep.Add(r);
            await r.Register(ConnectionId.Generate());
            results.Add(await r.ReadType());
        }
        Assert.Equal(5, results.Count(x => x == RelayMessageType.Registered));
        Assert.Equal(4, results.Count(x => x == RelayMessageType.Denied));
        Assert.True(rig.Engine.RegisteredHosts <= 5);
        foreach (var r in keep) await r.DisposeAsync();
    }

    [Fact]
    public async Task RelayRefusesTlsOlderThan13()
    {
        await using var rig = await RelayRig.StartAsync();
        using var tcp = new TcpClient(); await tcp.ConnectAsync("127.0.0.1", rig.Port);
        await using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
        await Assert.ThrowsAnyAsync<Exception>(async () => await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = "127.0.0.1", EnabledSslProtocols = SslProtocols.Tls12,
        }));
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("oversized")]
    [InlineData("unknown-type")]
    [InlineData("wrong-first-message")]
    public async Task HostileFirstBytesAreDroppedAndTheRelayKeepsServing(string attack)
    {
        await using var rig = await RelayRig.StartAsync();
        await using var host = NewHost(rig, IdA, "H", out _);
        await RelayRig.WaitFor(() => host.RelayStatus == RelayStatus.Online);
        await using (var a = await Raw.OpenAsync(rig))
        {
            switch (attack)
            {
                case "garbage": await a.S.WriteAsync(RandomNumberGenerator.GetBytes(300)); break;
                case "oversized": { var h = new byte[5]; System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(h, 50_000_000); h[4] = (byte)RelayMessageType.Register; await a.S.WriteAsync(h); break; }
                case "unknown-type": await a.S.WriteAsync(new byte[] { 0, 0, 0, 0, 0x42 }); break;
                case "wrong-first-message": await a.W.WriteAsync(RelayMessageType.Registered, default); break;   // a relay->host message sent TO the relay
            }
            await a.S.FlushAsync();
            Assert.True(await a.ClosedWithin(4000));
        }
        var stream = await RelayClient.ConnectToHostAsync(rig.Endpoint(), IdA, default);
        await using var v = await ViewerSession.ConnectAsync(stream, "u", host.Password, new ListAudit(), Permissions.All, default);
        Assert.Equal("H", v.HostName);
    }

    [Fact]
    public async Task SessionLimitIsEnforcedWithTheGenericAnswer()
    {
        await using var rig = await RelayRig.StartAsync(o => o.MaxConcurrentSessions = 1);
        await using var h1 = NewHost(rig, IdA, "ONE", out _);
        await using var h2 = NewHost(rig, IdB, "TWO", out _);
        await RelayRig.WaitFor(() => h1.RelayStatus == RelayStatus.Online && h2.RelayStatus == RelayStatus.Online);
        var s1 = await RelayClient.ConnectToHostAsync(rig.Endpoint(), IdA, default);
        await using var v1 = await ViewerSession.ConnectAsync(s1, "u", h1.Password, new ListAudit(), Permissions.All, default);
        var e = await Assert.ThrowsAsync<ConnectFailedException>(() => RelayClient.ConnectToHostAsync(rig.Endpoint(), IdB, default));
        Assert.Equal(ConnectFailure.NotFound, e.Failure);                     // no hint that the relay is "full"
    }

    [Fact]
    public async Task ConcurrentSessionsAreIsolated_NoCrossTalkBetweenPairs()
    {
        await using var rig = await RelayRig.StartAsync();
        await using var h1 = NewHost(rig, IdA, "HOST-ONE", out _);
        await using var h2 = NewHost(rig, IdB, "HOST-TWO", out _);
        await RelayRig.WaitFor(() => h1.RelayStatus == RelayStatus.Online && h2.RelayStatus == RelayStatus.Online);
        var t1 = Task.Run(async () => await ViewerSession.ConnectAsync(await RelayClient.ConnectToHostAsync(rig.Endpoint(), IdA, default), "a", h1.Password, new ListAudit(), Permissions.All, default));
        var t2 = Task.Run(async () => await ViewerSession.ConnectAsync(await RelayClient.ConnectToHostAsync(rig.Endpoint(), IdB, default), "b", h2.Password, new ListAudit(), Permissions.All, default));
        await using var v1 = await t1; await using var v2 = await t2;
        Assert.Equal("HOST-ONE", v1.HostName);
        Assert.Equal("HOST-TWO", v2.HostName);
        // a password for host two does not open host one through the relay either
        var wrong = await Assert.ThrowsAsync<ConnectFailedException>(async () =>
            await ViewerSession.ConnectAsync(await RelayClient.ConnectToHostAsync(rig.Endpoint(), IdA, default), "x", h2.Password, new ListAudit(), Permissions.All, default));
        Assert.NotEqual(ConnectFailure.Network, wrong.Failure);
    }

    [Fact]
    public async Task RelayLogsContainMetadataButNeverSecretsOrContent()
    {
        await using var rig = await RelayRig.StartAsync();
        await using var host = NewHost(rig, IdA, "SECRETHOSTNAME-PC", out _);
        await RelayRig.WaitFor(() => host.RelayStatus == RelayStatus.Online);
        var password = host.Password;
        var stream = await RelayClient.ConnectToHostAsync(rig.Endpoint(), IdA, default);
        var v = await ViewerSession.ConnectAsync(stream, "SECRETVIEWERNAME", password, new ListAudit(), Permissions.All, default);
        var token = v.ResumeToken;
        v.Start();
        await Task.Delay(300);
        await v.DisposeAsync();
        await RelayRig.WaitFor(() => rig.Engine.ActiveSessions == 0);
        var logs = rig.Logs.All;
        Assert.Contains(IdA, logs);                                           // metadata IS logged (that is the audit value)
        foreach (var secret in new[] { RelayRig.Key, password, token, "SECRETVIEWERNAME", "SECRETHOSTNAME-PC" })
            Assert.DoesNotContain(secret, logs);
    }
}
