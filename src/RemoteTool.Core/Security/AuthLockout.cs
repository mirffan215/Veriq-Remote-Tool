namespace RemoteTool.Core.Security;

/// <summary>Per-source brute-force protection: <see cref="MaxFailures"/> failures block the source for <see cref="BlockDuration"/>.</summary>
public sealed class AuthLockout
{
    public const int MaxFailures = 5;
    public static readonly TimeSpan BlockDuration = TimeSpan.FromMinutes(15);

    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new();

    private sealed class Entry { public int Failures; public DateTimeOffset? BlockedUntil; public DateTimeOffset Last; }

    public AuthLockout(TimeProvider? time = null) { _time = time ?? TimeProvider.System; }

    public bool IsBlocked(string source)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(source, out var e) || e.BlockedUntil is null) return false;
            if (e.BlockedUntil > _time.GetUtcNow()) return true;
            _entries.Remove(source);
            return false;
        }
    }

    /// <summary>Records a failed attempt. Returns true when this failure caused the source to become blocked.</summary>
    public bool RegisterFailure(string source)
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            Sweep(now);
            if (!_entries.TryGetValue(source, out var e)) _entries[source] = e = new Entry();
            e.Last = now;
            e.Failures++;
            if (e.Failures < MaxFailures) return false;
            e.BlockedUntil = now + BlockDuration;
            return true;
        }
    }

    public void RegisterSuccess(string source) { lock (_gate) _entries.Remove(source); }

    private void Sweep(DateTimeOffset now)
    {
        if (_entries.Count < 1024) return;
        foreach (var k in _entries.Where(kv => now - kv.Value.Last > BlockDuration && (kv.Value.BlockedUntil ?? now) <= now).Select(kv => kv.Key).ToList())
            _entries.Remove(k);
    }
}
