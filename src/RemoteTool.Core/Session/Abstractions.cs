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

/// <summary>Optional capability of an <see cref="IInputInjector"/>: Secure Attention Sequence (only available when running as the Windows service).</summary>
public interface ISpecialKeys { void SendCtrlAltDel(); }

/// <summary>
/// Optional capability of an <see cref="IFrameProducer"/>: hardware/software H.264 for the monitor. Returns null when nothing changed.
/// Throw <see cref="CodecUnavailableException"/> to make the host fall back to the tile codec for the rest of the session.
/// </summary>
public interface IH264Source
{
    bool H264Available { get; }
    VideoFrameMessage? NextH264(int monitorIndex, bool keyframe, int bitrateKbps);
}

public sealed class CodecUnavailableException : Exception
{
    public CodecUnavailableException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Injects remote input on the host. Must release every held key/button in <see cref="ReleaseAll"/>.</summary>
public interface IInputInjector : IDisposable
{
    void Mouse(MonitorInfo monitor, MouseEventMessage e);
    void Key(KeyEventMessage e);
    void ReleaseAll();
}

/// <param name="Recording">True when this host will record the session (the consent UI must say so).</param>
/// <param name="SecurityCode">Both sides show this 6-digit code; if the viewer reports a different one, someone is in the middle: deny.</param>
/// <param name="ConsentOnly">The viewer used no password: this click is the only authorisation.</param>
public sealed record ConsentRequestInfo(string ViewerName, string Source, bool ViaRelay, Permissions Requested, Permissions Allowed, bool Recording = false,
    string? SecurityCode = null, bool ConsentOnly = false);
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
    IReadOnlyList<string>? IpAllowList = null,
    /// <summary>Accept connections that only need the user's Accept click (the AnyDesk-style default). False for the unattended service.</summary>
    bool AllowConsentOnly = true)
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
    /// <summary>The other PC only accepts connections with a password (not just a click).</summary>
    PasswordRequired,
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

public enum DecodeStatus { NeedMoreInput, Frame, Failed }

public sealed record DecodedFrame(byte[] Bgra, int Width, int Height);

/// <summary>Viewer-side H.264 decoder (Media Foundation on Windows). Any <see cref="DecodeStatus.Failed"/> triggers fallback to the tile codec.</summary>
public interface IH264Decoder : IDisposable
{
    DecodeStatus TryDecode(byte[] annexB, bool keyframe, out DecodedFrame? frame);
}
