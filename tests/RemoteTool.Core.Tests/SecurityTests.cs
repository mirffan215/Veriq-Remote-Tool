using RemoteTool.Core.Audit;
using RemoteTool.Core.Config;
using RemoteTool.Core.Security;

namespace RemoteTool.Core.Tests;

[Collection("EditionState")]
public class SecurityTests
{
    private sealed class FakeTime : TimeProvider
    {
        public DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void LockoutBlocksAfterFiveFailuresForFifteenMinutes()
    {
        var t = new FakeTime();
        var l = new AuthLockout(t);
        for (var i = 0; i < 4; i++) Assert.False(l.RegisterFailure("a"));
        Assert.False(l.IsBlocked("a"));
        Assert.True(l.RegisterFailure("a"));
        Assert.True(l.IsBlocked("a"));
        Assert.False(l.IsBlocked("b"));
        t.Now += TimeSpan.FromMinutes(14);
        Assert.True(l.IsBlocked("a"));
        t.Now += TimeSpan.FromMinutes(2);
        Assert.False(l.IsBlocked("a"));
    }

    [Fact]
    public void ProofsBindToFingerprintsAndRoles()
    {
        var salt = new byte[16];
        var key = PasswordHandshake.DeriveKey("abcd-2345", salt);
        Assert.Equal(key, PasswordHandshake.DeriveKey("ABCD2345", salt)); // normalisation
        byte[] nv = new byte[32], nh = new byte[32], fv = { 1 }, fh = { 2 };
        var p = PasswordHandshake.ViewerProof(key, nv, nh, fv, fh);
        Assert.NotEqual(p, PasswordHandshake.ViewerProof(key, nv, nh, new byte[] { 9 }, fh));
        Assert.NotEqual(p, PasswordHandshake.ViewerProof(PasswordHandshake.DeriveKey("WRONGPW2", salt), nv, nh, fv, fh));
        Assert.NotEqual(p, PasswordHandshake.HostProof(key, nv, nh, fv, fh)); // no reflection of one proof as the other
    }

    [Fact]
    public void PasswordsAreEightCharsFromAlphabet()
    {
        for (var i = 0; i < 200; i++)
        {
            var p = PasswordGenerator.Generate();
            Assert.Equal(8, p.Length);
            Assert.All(p, c => Assert.Contains(c, PasswordGenerator.Alphabet));
        }
    }

    [Fact]
    public void IdsAreTwelveDigitsNeverLeadingZero_AndRandom()
    {
        var seen = new HashSet<string>();
        var digitCounts = new int[10];
        for (var i = 0; i < 20000; i++)
        {
            var id = ConnectionId.Generate();
            Assert.Equal(12, id.Length);
            Assert.True(ConnectionId.IsValid(id));
            Assert.NotEqual('0', id[0]);
            seen.Add(id);
            foreach (var c in id[1..]) digitCounts[c - '0']++;
        }
        Assert.Equal(20000, seen.Count);                                   // no collisions in 20k draws
        var expected = 20000 * 11 / 10.0;                                   // 11 free digits per ID, uniform
        Assert.All(digitCounts, n => Assert.InRange(n, expected * 0.95, expected * 1.05));   // no digit bias
    }

    [Theory]
    [InlineData(10, "123 456 789 0")]
    [InlineData(11, "123 456 789 01")]
    [InlineData(12, "123 456 789 012")]
    public void AcceptedLengthsFormatInGroupsOfThree(int length, string expected)
    {
        var id = "123456789012"[..length];
        Assert.True(ConnectionId.IsValid(id));
        Assert.Equal(expected, ConnectionId.Format(id));
        Assert.True(ConnectionId.TryParseId(expected, out var parsed));
        Assert.Equal(id, parsed);
        Assert.Equal(length, ConnectionId.Generate(length).Length);
    }

    [Theory]
    [InlineData("123456789")]          // 9 digits: too short
    [InlineData("1234567890123")]      // 13 digits: too long
    [InlineData("0123456789012")]
    [InlineData("012345678901")]       // leading zero
    [InlineData("12345678901a")]
    [InlineData("")]
    public void InvalidCodesAreRejected(string id) => Assert.False(ConnectionId.IsValid(id));

    [Theory]
    [InlineData("123 456 789 012", "ById")]
    [InlineData("1234567890", "ById")]
    [InlineData("192.168.1.5:21118", "Direct")]
    [InlineData("pc-01.corp.local", "Direct")]
    [InlineData("[::1]:9000", "Direct")]
    public void ConnectTargetParses(string input, string kind)
    {
        Assert.True(ConnectTarget.TryParse(input, out var t));
        Assert.Equal(kind, t!.GetType().Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData("host:99999")]
    [InlineData("host with space")]
    [InlineData("012 345 678:x")]
    [InlineData("123 456 789")]
    public void ConnectTargetRejectsGarbage(string input) => Assert.False(ConnectTarget.TryParse(input, out _));

    [Fact]
    public void IdIsPersistentAcrossRestartsAndCanBeRegenerated()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        try
        {
            var file = Path.Combine(dir, "settings.json");
            var id1 = new SettingsStore(file).Load().Id;
            var s2 = new SettingsStore(file);
            Assert.Equal(id1, s2.Load().Id);
            Assert.NotEqual(id1, s2.RegenerateId());
            Assert.Equal(s2.Current.Id, new SettingsStore(file).Load().Id);
            File.WriteAllText(file, "{ corrupt");
            Assert.True(ConnectionId.IsValid(new SettingsStore(file).Load().Id));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void AuditLogWritesJsonLinesRotatesAndRefusesSecrets()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        try
        {
            var log = new JsonlAuditLog(dir, "host", maxFileBytes: 300);
            for (var i = 0; i < 10; i++) log.Write("session_start", ("viewer", "alice"), ("n", i));
            var files = Directory.GetFiles(dir, "*.jsonl");
            Assert.True(files.Length > 1);
            var line = File.ReadAllLines(files[0])[0];
            using var doc = System.Text.Json.JsonDocument.Parse(line);
            Assert.Equal("session_start", doc.RootElement.GetProperty("event").GetString());
            Assert.Throws<ArgumentException>(() => log.Write("x", ("password", "hunter2")));
            Assert.Throws<ArgumentException>(() => log.Write("x", ("screenshot", "...")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void PortableFlagRedirectsStorage()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            Assert.False(StoragePaths.Detect(dir).Portable);
            File.WriteAllText(Path.Combine(dir, "portable.flag"), "");
            var p = StoragePaths.Detect(dir);
            Assert.True(p.Portable);
            Assert.StartsWith(dir, p.SettingsDirectory);
        }
        finally { Directory.Delete(dir, true); }
    }
}
