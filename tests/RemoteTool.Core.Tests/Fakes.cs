using System.Collections.Concurrent;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Core.Tests;

public sealed class FakeProducer : IFrameProducer
{
    private uint _seq;
    public IReadOnlyList<MonitorInfo> GetMonitors() => new[] { new MonitorInfo(0, 0, 0, 64, 64, true, "Fake") };
    public FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe)
        => new(0, ++_seq, 64, 64, keyframe, new[] { new TileRect(0, 0, 64, 64, new byte[] { 1, 2, 3, 4 }) });
    public CursorShape GetCursorShape() => CursorShape.Arrow;
    public void Dispose() { }
}

public sealed class FakeInjector : IInputInjector
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
    public ConsentRequestInfo? Last;
    public Task<ConsentDecision> RequestAsync(ConsentRequestInfo info, CancellationToken ct)
    {
        Last = info;
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
