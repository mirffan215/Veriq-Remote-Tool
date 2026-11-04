namespace RemoteTool.Relay;

/// <summary>Per-key sliding-window counter (in memory, clock-injectable).</summary>
public sealed class SlidingWindowLimiter
{
    private readonly int _limit;
    private readonly TimeSpan _window;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, Queue<DateTimeOffset>> _hits = new();
    private DateTimeOffset _lastSweep;

    public SlidingWindowLimiter(int limit, TimeSpan window, TimeProvider? time = null)
    {
        _limit = limit;
        _window = window;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>True if the key is still under its limit; records a hit in that case.</summary>
    public bool TryHit(string key)
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            var q = Trim(key, now);
            if (q.Count >= _limit) return false;
            q.Enqueue(now);
            return true;
        }
    }

    /// <summary>Records a hit unconditionally.</summary>
    public void Hit(string key) { lock (_gate) { var now = _time.GetUtcNow(); Trim(key, now).Enqueue(now); } }

    public bool IsLimited(string key) { lock (_gate) return Trim(key, _time.GetUtcNow()).Count >= _limit; }

    private Queue<DateTimeOffset> Trim(string key, DateTimeOffset now)
    {
        if (now - _lastSweep > _window)
        {
            _lastSweep = now;
            foreach (var k in _hits.Where(kv => kv.Value.Count == 0 || now - kv.Value.Peek() > _window).Select(kv => kv.Key).ToList())
                if (_hits[k].All(t => now - t > _window)) _hits.Remove(k);
        }
        if (!_hits.TryGetValue(key, out var q)) _hits[key] = q = new Queue<DateTimeOffset>();
        while (q.Count > 0 && now - q.Peek() > _window) q.Dequeue();
        return q;
    }
}
