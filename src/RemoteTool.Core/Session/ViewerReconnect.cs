using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

/// <summary>Re-establishes a dropped session using the single-use resume ticket (no new password, no new consent dialog).</summary>
public static class ViewerReconnect
{
    public static bool IsRecoverable(ByeReason reason) => reason is ByeReason.Timeout or ByeReason.ProtocolError;

    /// <param name="dial">Opens a fresh transport (direct TCP or relay) to the same host.</param>
    /// <param name="onAttempt">Optional progress callback (attempt number, 1-based).</param>
    public static async Task<ViewerSession> ResumeAsync(Func<CancellationToken, Task<Stream>> dial, string viewerName, string resumeToken,
        IAuditLog audit, Permissions requested, CancellationToken ct, int maxAttempts = 8, TimeSpan? firstDelay = null, Action<int>? onAttempt = null)
    {
        var delay = firstDelay ?? TimeSpan.FromSeconds(1);
        ConnectFailedException? last = null;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            onAttempt?.Invoke(attempt);
            try
            {
                var transport = await dial(ct).ConfigureAwait(false);
                var s = await ViewerSession.ConnectAsync(transport, viewerName, resumeToken, audit, requested, ct, resume: true).ConfigureAwait(false);
                audit.Write("session_resume_ok", ("attempt", attempt));
                return s;
            }
            catch (ConnectFailedException e) when (e.Failure is ConnectFailure.Network or ConnectFailure.Timeout or ConnectFailure.Protocol or ConnectFailure.NotFound)
            {
                last = e; // network still down (or host/relay not back yet): keep trying within the host's 2-minute window
            }
            await Task.Delay(delay, ct).ConfigureAwait(false);
            delay = TimeSpan.FromTicks(Math.Min(delay.Ticks * 2, TimeSpan.FromSeconds(15).Ticks));
        }
        audit.Write("session_resume_failed");
        throw last ?? new ConnectFailedException(ConnectFailure.Network, "Could not reconnect.");
    }
}
