using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

/// <summary>Produces encoded screen updates. Implemented by RemoteTool.Capture (Windows) or a fake in tests.</summary>
public interface IFrameProducer : IDisposable
{
    IReadOnlyList<MonitorInfo> GetMonitors();
    /// <summary>Returns null when nothing changed since the last call (unless <paramref name="keyframe"/>).</summary>
    FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe);
    CursorShape GetCursorShape();
}

/// <summary>Injects remote input on the host. Must release every held key/button in <see cref="ReleaseAll"/>.</summary>
public interface IInputInjector : IDisposable
{
    void Mouse(MonitorInfo monitor, MouseEventMessage e);
    void Key(KeyEventMessage e);
    void ReleaseAll();
}

public sealed record ConsentRequestInfo(string ViewerName, string Source, bool ViaRelay, Permissions Requested, Permissions Allowed);
public sealed record ConsentDecision(bool Granted, Permissions Permissions);

public interface IConsentProvider
{
    Task<ConsentDecision> RequestAsync(ConsentRequestInfo info, CancellationToken ct);
}

/// <summary>Immutable snapshot of host-side policy; swap atomically via <see cref="HostService.Policy"/>.</summary>
public sealed record HostPolicy(
    string DisplayName,
    bool ViewOnly = false,
    bool AllowClipboard = true,
    bool AllowFileTransfer = true,
    IReadOnlyList<string>? IpAllowList = null)
{
    public Permissions Allowed =>
        (ViewOnly ? Permissions.None : Permissions.Control)
        | (AllowClipboard ? Permissions.Clipboard : Permissions.None)
        | (AllowFileTransfer ? Permissions.FileTransfer : Permissions.None);
}

public sealed record SessionInfo(Guid Id, string ViewerName, string Source, Permissions Permissions, DateTimeOffset StartedAt);

public enum ConnectFailure
{
    Network, NotFound, BadPassword, Blocked, Busy, Denied, VersionMismatch, NotAllowed,
    /// <summary>Host proof did not verify: wrong peer or an active man-in-the-middle.</summary>
    PeerAuthenticationFailed,
    Timeout, Protocol,
}

public sealed class ConnectFailedException : Exception
{
    public ConnectFailure Failure { get; }
    public ConnectFailedException(ConnectFailure failure, string message, Exception? inner = null) : base(message, inner) { Failure = failure; }
}

public static class NameSanitizer
{
    public static string Clean(string? s, string fallback = "unknown")
    {
        if (string.IsNullOrWhiteSpace(s)) return fallback;
        var cleaned = new string(s.Where(c => !char.IsControl(c)).ToArray()).Trim();
        if (cleaned.Length > ProtocolConstants.MaxNameChars) cleaned = cleaned[..ProtocolConstants.MaxNameChars];
        return cleaned.Length == 0 ? fallback : cleaned;
    }
}
