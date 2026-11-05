using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RemoteTool.Core.Relay;
using RemoteTool.Core.Session;
using RemoteTool.Relay;

namespace RemoteTool.Relay.Tests;

public sealed class CapturingObserver : ISpliceObserver
{
    private readonly object _g = new();
    private readonly List<byte> _bytes = new();
    public void OnBytes(bool hostToViewer, ReadOnlySpan<byte> data) { lock (_g) _bytes.AddRange(data.ToArray()); }
    public byte[] Snapshot() { lock (_g) return _bytes.ToArray(); }
}

public sealed class CapturingLogger : ILoggerProvider
{
    private readonly List<string> _lines = new();
    public string All { get { lock (_lines) return string.Join("\n", _lines); } }
    public ILogger CreateLogger(string categoryName) => new L(this);
    public void Dispose() { }
    private sealed class L : ILogger
    {
        private readonly CapturingLogger _o; public L(CapturingLogger o) { _o = o; }
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        { lock (_o._lines) _o._lines.Add(formatter(state, exception) + (exception is null ? "" : " " + exception)); }
    }
}

public sealed class FixedId : IIdProvider
{
    public string Id { get; private set; }
    public int Regenerations;
    public FixedId(string id) { Id = id; }
    public string Regenerate() { Regenerations++; return Id = RemoteTool.Core.Config.ConnectionId.Generate(); }
}

public sealed class RelayRig : IAsyncDisposable
{
    public const string Key = "test-access-key";
    private readonly WebApplication _app;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rt-relay-" + Guid.NewGuid().ToString("N"));
    public int Port { get; }
    public CapturingObserver Observer { get; } = new();
    public RelayEngine Engine => _app.Services.GetRequiredService<RelayEngine>();
    public string Fingerprint { get; }

    public CapturingLogger Logs { get; } = new();

    private RelayRig(Action<RelayOptions>? tweak)
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        Port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        _app = RelayHost.Build(Array.Empty<string>(), o =>
        {
            o.Port = Port; o.HealthPort = 0; o.AccessKey = Key; o.DataDirectory = _dir;
            o.PendingTimeoutSeconds = 5; o.PingIntervalSeconds = 2; o.ConnectsPerMinutePerIp = 1000; o.FailedLookupsPerMinutePerIp = 1000;
            tweak?.Invoke(o);
        }, Observer, Logs);
        _app.Logger.LogInformation("test relay");
        Fingerprint = Convert.ToHexString(SHA256.HashData(new X509Certificate2(Path.Combine(_dir, "relay-selfsigned.pfx")).GetRawCertData()));
    }

    public static async Task<RelayRig> StartAsync(Action<RelayOptions>? tweak = null)
    {
        var r = new RelayRig(tweak);
        await r._app.StartAsync();
        return r;
    }

    public RelayEndpoint Endpoint(string key = Key, string? fp = null) => new("127.0.0.1", Port, key, fp ?? Fingerprint);

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        try { Directory.Delete(_dir, true); } catch { }
    }

    public static async Task WaitFor(Func<bool> cond, int seconds = 10)
    {
        var until = DateTime.UtcNow.AddSeconds(seconds);
        while (!cond() && DateTime.UtcNow < until) await Task.Delay(25);
        Assert.True(cond(), "condition not reached in time");
    }
}
