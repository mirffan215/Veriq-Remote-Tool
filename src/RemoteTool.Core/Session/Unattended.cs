using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

/// <summary>
/// Policy for unattended (permanent-password) sessions. Implemented by the Windows service: it knows whether someone is sitting at the
/// machine and can ask them through the session helper.
/// </summary>
public interface IUnattendedPolicy
{
    /// <summary>The most an unattended session may ever do (the service keeps this to Control; no clipboard/files without a user).</summary>
    Permissions Permissions { get; }
    /// <summary>Allow/deny for this specific connection (e.g. ask the user if one is at the screen, auto-allow on the login screen).</summary>
    Task<ConsentDecision> DecideAsync(ConsentRequestInfo info, CancellationToken ct);
}

/// <summary>
/// Trips after too many failures from ANY source inside a window: the permanent password is online-guessable for ever, and relay-reported
/// source addresses can be varied by a distributed attacker, so per-source lockout alone is not enough.
/// </summary>
public sealed class FailureBreaker
{
    private readonly int _max;
    private readonly TimeSpan _window;
    private readonly TimeProvider _time;
    private readonly object _gate = new();
    private readonly Queue<DateTimeOffset> _failures = new();
    private DateTimeOffset? _trippedUntil;

    public FailureBreaker(int maxFailures = 20, TimeSpan? window = null, TimeProvider? time = null)
    {
        _max = maxFailures;
        _window = window ?? TimeSpan.FromMinutes(15);
        _time = time ?? TimeProvider.System;
    }

    public bool IsTripped { get { lock (_gate) return _trippedUntil is { } t && t > _time.GetUtcNow(); } }

    /// <summary>Returns true if this failure tripped the breaker.</summary>
    public bool RegisterFailure()
    {
        lock (_gate)
        {
            var now = _time.GetUtcNow();
            while (_failures.Count > 0 && now - _failures.Peek() > _window) _failures.Dequeue();
            _failures.Enqueue(now);
            if (_failures.Count < _max) return false;
            _trippedUntil = now + _window;
            _failures.Clear();
            return true;
        }
    }
}
