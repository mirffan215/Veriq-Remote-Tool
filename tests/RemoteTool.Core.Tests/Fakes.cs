using System.Collections.Concurrent;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

public sealed class FakeProducer : IFrameProducer
{
    private uint _seq;
    private static readonly MonitorInfo[] Mons =
    {
        new(0, 0, 0, 64, 64, true, "Primary"),
        new(1, 64, 0, 32, 48, false, "Second"),
    };
    public IReadOnlyList<MonitorInfo> GetMonitors() => Mons;
    public FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe)
    {
        var m = Mons[monitorIndex];
        return new(m.Index, ++_seq, m.Width, m.Height, keyframe, new[] { new TileRect(0, 0, m.Width, m.Height, new byte[] { 1, 2, 3, 4 }) });
    }
    public CursorShape GetCursorShape() => CursorShape.Arrow;
    public void Dispose() { }
}

public class FakeInjector : IInputInjector
{
    public ConcurrentQueue<string> Events { get; } = new();
    public int ReleaseAllCalls;
    public void Mouse(MonitorInfo monitor, MouseEventMessage e) => Events.Enqueue($"mouse:{e.Kind}:{e.X}:{e.Y}");
    public void Key(KeyEventMessage e) => Events.Enqueue($"key:{e.VirtualKey}:{(e.KeyUp ? "up" : "down")}");
    public void ReleaseAll() => Interlocked.Increment(ref ReleaseAllCalls);
    public void Dispose() { }
}

public sealed class FakeConsent : IConsentProvider
{
    public bool Allow = true;
    public int Calls;
    public ConsentRequestInfo? Last;
    public Task<ConsentDecision> RequestAsync(ConsentRequestInfo info, CancellationToken ct)
    {
        Last = info;
        Interlocked.Increment(ref Calls);
        return Task.FromResult(new ConsentDecision(Allow, info.Allowed));
    }
}

public sealed class ListAudit : RemoteTool.Core.Audit.IAuditLog
{
    public ConcurrentQueue<string> Lines { get; } = new();
    public void Write(string eventName, params (string Key, object? Value)[] fields)
        => Lines.Enqueue(eventName + " " + string.Join(" ", fields.Select(f => $"{f.Key}={f.Value}")));
    public bool Has(string evt) => Lines.Any(l => l.StartsWith(evt));
}

public sealed class FakeClipboard : IClipboardAccess
{
    private string? _text;
    public event Action? Changed;
    public string? GetText() { lock (this) return _text; }
    /// <summary>Like the OS: setting the clipboard raises Changed.</summary>
    public void SetText(string text) { lock (this) _text = text; Changed?.Invoke(); }
    public void UserCopies(string text) => SetText(text);
    public void Dispose() { }
}

public sealed class AutoPrompt : IFileTransferPrompt
{
    public bool Answer = true;
    public readonly List<FileOfferInfo> Seen = new();
    public Task<bool> ConfirmAsync(FileOfferInfo info, CancellationToken ct) { lock (Seen) Seen.Add(info); return Task.FromResult(Answer); }
}

/// <summary>TCP forwarder (no TLS termination) that can cut every connection to simulate a network drop.</summary>
public sealed class SeverableProxy : IDisposable
{
    private readonly System.Net.Sockets.TcpListener _l = new(System.Net.IPAddress.Loopback, 0);
    private readonly List<System.Net.Sockets.TcpClient> _all = new();
    private readonly int _target;
    public int Port { get; }

    public SeverableProxy(int targetPort)
    {
        _target = targetPort;
        _l.Start();
        Port = ((System.Net.IPEndPoint)_l.LocalEndpoint).Port;
        _ = Task.Run(Loop);
    }

    private async Task Loop()
    {
        while (true)
        {
            System.Net.Sockets.TcpClient c;
            try { c = await _l.AcceptTcpClientAsync(); } catch { return; }
            var up = new System.Net.Sockets.TcpClient();
            try { await up.ConnectAsync(System.Net.IPAddress.Loopback, _target); } catch { c.Dispose(); continue; }
            lock (_all) { _all.Add(c); _all.Add(up); }
            _ = Pump(c.GetStream(), up.GetStream());
            _ = Pump(up.GetStream(), c.GetStream());
        }
    }

    private static async Task Pump(Stream a, Stream b)
    {
        var buf = new byte[16384];
        try { int n; while ((n = await a.ReadAsync(buf)) > 0) await b.WriteAsync(buf.AsMemory(0, n)); } catch { }
        try { b.Dispose(); a.Dispose(); } catch { }
    }

    public void SeverAll() { lock (_all) { foreach (var c in _all) try { c.Dispose(); } catch { } _all.Clear(); } }
    public void Dispose() { _l.Stop(); SeverAll(); }
}

public sealed class TestProtector : RemoteTool.Core.Config.ISecretProtector
{
    public string Protect(string plaintext) => "TP:" + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(plaintext));
    public string Unprotect(string protectedText) => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(protectedText[3..]));
}

public sealed class SasInjector : FakeInjector, ISpecialKeys
{
    public int SasCalls;
    public void SendCtrlAltDel() => Interlocked.Increment(ref SasCalls);
}

public sealed class FakeUnattendedPolicy : IUnattendedPolicy
{
    public Permissions Permissions { get; set; } = Permissions.Control;
    public bool Allow = true;
    public int Calls;
    public Task<ConsentDecision> DecideAsync(ConsentRequestInfo info, CancellationToken ct)
    {
        Interlocked.Increment(ref Calls);
        return Task.FromResult(new ConsentDecision(Allow, info.Allowed));
    }
}

/// <summary>Producer that can speak H.264 (fake NAL bytes) and can be told to fail like a broken GPU encoder.</summary>
public sealed class H264FakeProducer : IFrameProducer, IH264Source
{
    private readonly FakeProducer _tiles = new();
    private uint _seq;
    public static volatile bool Fail;
    public bool H264Available => true;
    public IReadOnlyList<MonitorInfo> GetMonitors() => _tiles.GetMonitors();
    public FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe) => _tiles.NextFrame(monitorIndex, quality, keyframe);
    public VideoFrameMessage? NextH264(int monitorIndex, bool keyframe, int bitrateKbps)
    {
        if (Fail) throw new CodecUnavailableException("simulated encoder failure");
        return new VideoFrameMessage((byte)monitorIndex, ++_seq, 64, 64, keyframe, new byte[] { 0, 0, 0, 1, 0x65, 1, 2, 3 });
    }
    public CursorShape GetCursorShape() => CursorShape.Arrow;
    public void Dispose() { }
}

public sealed class FakeDecoder : IH264Decoder
{
    public static volatile bool Fail;
    public DecodeStatus TryDecode(byte[] annexB, bool keyframe, out DecodedFrame? frame)
    {
        if (Fail) { frame = null; return DecodeStatus.Failed; }
        frame = new DecodedFrame(new byte[64 * 64 * 4], 64, 64);
        return DecodeStatus.Frame;
    }
    public void Dispose() { }
}
