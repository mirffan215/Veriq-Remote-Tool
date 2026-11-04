using RemoteTool.Core.Audit;

namespace RemoteTool.Service.Helper;

/// <summary>A running helper: its pipe and a task that completes when the process is gone.</summary>
public interface IHelperProcess : IAsyncDisposable
{
    Stream Pipe { get; }
    Task Exited { get; }
    int ProcessId { get; }
}

public interface IHelperLauncher
{
    /// <summary>Starts a helper in the given session and returns once its pipe is connected. Throws if that is not possible (no console session yet).</summary>
    Task<IHelperProcess> LaunchAsync(int sessionId, CancellationToken ct);
    /// <summary>The session that currently owns the console (login screen or user), or null if none.</summary>
    int? ActiveSessionId();
}

/// <summary>
/// Keeps exactly one helper alive in the active console session: relaunches after crashes, and moves it when the console
/// session changes (fast user switching, logon/logoff, RDP reconnect).
/// </summary>
public sealed class HelperSupervisor : IAsyncDisposable
{
    private readonly IHelperLauncher _launcher;
    private readonly IAuditLog _audit;
    private readonly TimeSpan _retryDelay;
    private readonly CancellationTokenSource _cts = new();
    private readonly SemaphoreSlim _changed = new(0, int.MaxValue);
    private TaskCompletionSource<HelperChannel> _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private Task? _loop;
    private HelperChannel? _current;

    public HelperSupervisor(IHelperLauncher launcher, IAuditLog audit, TimeSpan? retryDelay = null)
    {
        _launcher = launcher;
        _audit = audit;
        _retryDelay = retryDelay ?? TimeSpan.FromSeconds(3);
    }

    /// <summary>Raised on the supervisor thread whenever a new helper connection is established.</summary>
    public event Action<HelperChannel>? ChannelReady;
    public HelperChannel? Current => _current;

    public void Start() => _loop ??= Task.Run(LoopAsync);

    /// <summary>Call from the service's session-change notification.</summary>
    public void NotifySessionChanged() { try { _changed.Release(); } catch (SemaphoreFullException) { } }

    public async Task<HelperChannel> GetChannelAsync(TimeSpan timeout)
    {
        var t = _ready.Task;
        if (_current is { } c && !c.Closed.IsCompleted) return c;
        return await t.WaitAsync(timeout, _cts.Token).ConfigureAwait(false);
    }

    private async Task LoopAsync()
    {
        var ct = _cts.Token;
        while (!ct.IsCancellationRequested)
        {
            IHelperProcess? proc = null;
            HelperChannel? ch = null;
            try
            {
                var sid = _launcher.ActiveSessionId();
                if (sid is null) { await Task.Delay(_retryDelay, ct).ConfigureAwait(false); continue; }
                proc = await _launcher.LaunchAsync(sid.Value, ct).ConfigureAwait(false);
                ch = new HelperChannel(proc.Pipe);
                await ch.StartAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
                _current = ch;
                _audit.Write("helper_started", ("session", ch.Hello.SessionId), ("pid", ch.Hello.ProcessId), ("user", ch.Hello.UserName));
                var ready = _ready;
                ready.TrySetResult(ch);
                ChannelReady?.Invoke(ch);

                // run until the helper dies or the console session moves
                var moved = _changed.WaitAsync(ct);
                var done = await Task.WhenAny(proc.Exited, ch.Closed, moved).ConfigureAwait(false);
                _audit.Write("helper_stopped", ("reason", done == moved ? "session-change" : "exited"));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e) when (e is IOException or TimeoutException or InvalidOperationException or System.ComponentModel.Win32Exception
                                           or RemoteTool.Core.Protocol.ProtocolException or UnauthorizedAccessException)
            {
                _audit.Write("helper_error", ("error", e.GetType().Name));
            }
            finally
            {
                _current = null;
                if (_ready.Task.IsCompleted) _ready = new TaskCompletionSource<HelperChannel>(TaskCreationOptions.RunContinuationsAsynchronously);
                if (ch is not null) await ch.DisposeAsync().ConfigureAwait(false);
                if (proc is not null) await proc.DisposeAsync().ConfigureAwait(false);
            }
            try { await Task.Delay(_retryDelay, ct).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
        }
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_loop is not null) { try { await _loop.ConfigureAwait(false); } catch { } }
        _cts.Dispose();
    }
}
