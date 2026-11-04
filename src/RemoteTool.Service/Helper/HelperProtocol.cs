using RemoteTool.Core.Protocol;

namespace RemoteTool.Service.Helper;

/// <summary>
/// Local protocol between the service (SYSTEM, session 0) and the per-session helper. Same framing as the network protocol
/// but a separate type space. Requests are strictly request/response (one outstanding), input messages are fire-and-forget,
/// the helper may push events (emergency hotkey, banner Disconnect).
/// </summary>
public enum HelperMessage : byte
{
    // service -> helper
    GetMonitors = 1, NextFrame = 2, NextH264 = 3, GetCursor = 4, GetDesktop = 5, Mouse = 6, Key = 7, ReleaseAll = 8,
    ShowBanner = 9, HideBanner = 10, AskConsent = 11, Shutdown = 12,
    // helper -> service
    Hello = 64, Monitors = 65, Frame = 66, Video = 67, Cursor = 68, Desktop = 69, ConsentAnswer = 70, Error = 71,
    EmergencyHotkey = 80, BannerDisconnect = 81,
}

public static class HelperTypes
{
    public static bool IsKnown(byte t) => t is >= 1 and <= 12 or >= 64 and <= 71 or 80 or 81;
    public static bool IsResponse(HelperMessage m) => m is >= HelperMessage.Hello and <= HelperMessage.Error;
    public const int MaxPayload = 32 * 1024 * 1024;
}

public sealed class HelperException : IOException
{
    public HelperException(string message, Exception? inner = null) : base(message, inner) { }
}

public sealed record HelperHello(int ProcessId, int SessionId, bool H264, string UserName)
{
    public byte[] Serialize() => new ProtoWriter().I32(ProcessId).I32(SessionId).Bool(H264).Str(UserName).ToArray();

    public static HelperHello Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new HelperHello(r.I32(), r.I32(), r.Bool(), r.Str(128));
        r.EnsureEnd();
        return m;
    }
}

public static class HelperCodec
{
    public static byte[] NextFrameRequest(int monitor, int quality, bool key) => new ProtoWriter().U8((byte)monitor).U8((byte)quality).Bool(key).ToArray();
    public static (int Monitor, int Quality, bool Key) ParseNextFrame(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = (r.U8(), r.U8(), r.Bool());
        r.EnsureEnd();
        return m;
    }

    public static byte[] NextH264Request(int monitor, bool key, int kbps) => new ProtoWriter().U8((byte)monitor).Bool(key).I32(kbps).ToArray();
    public static (int Monitor, bool Key, int Kbps) ParseNextH264(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = (r.U8(), r.Bool(), r.I32());
        r.EnsureEnd();
        if (m.Item3 is < 100 or > 100_000) throw new ProtocolException("bitrate out of range");
        return m;
    }

    /// <summary>Optional payload: 0 = nothing changed, 1 + bytes.</summary>
    public static byte[] Optional(byte[]? data) => data is null ? new byte[] { 0 } : new ProtoWriter().U8(1).Bytes(data).ToArray();
    public static byte[]? ParseOptional(byte[] p)
    {
        var r = new ProtoReader(p);
        var has = r.Bool();
        var data = has ? r.Bytes(HelperTypes.MaxPayload) : null;
        r.EnsureEnd();
        return data;
    }

    public static byte[] MouseRequest(MonitorInfo monitor, MouseEventMessage e)
        => new ProtoWriter().U8(monitor.Index).I32(monitor.X).I32(monitor.Y).I32(monitor.Width).I32(monitor.Height).Bool(monitor.Primary).Bytes(e.Serialize()).ToArray();

    public static (MonitorInfo Monitor, MouseEventMessage Event) ParseMouse(byte[] p)
    {
        var r = new ProtoReader(p);
        var mon = new MonitorInfo(r.U8(), r.I32(), r.I32(), r.I32(), r.I32(), r.Bool(), "");
        var ev = MouseEventMessage.Parse(r.Bytes(64));
        r.EnsureEnd();
        return (mon, ev);
    }

    public static byte[] BannerRequest(string viewer, bool recording) => new ProtoWriter().Str(viewer).Bool(recording).ToArray();
    public static (string Viewer, bool Recording) ParseBanner(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = (r.Str(ProtocolConstants.MaxNameChars), r.Bool());
        r.EnsureEnd();
        return m;
    }

    public static byte[] ConsentRequest(HelperConsentInfo i)
        => new ProtoWriter().Str(i.ViewerName).Str(i.Source).Bool(i.ViaRelay).U8((byte)i.Requested).U8((byte)i.Allowed).Bool(i.Recording).ToArray();
    public static HelperConsentInfo ParseConsent(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new HelperConsentInfo(r.Str(ProtocolConstants.MaxNameChars), r.Str(128), r.Bool(), (Permissions)r.U8(), (Permissions)r.U8(), r.Bool());
        r.EnsureEnd();
        return m;
    }

    public static byte[] ConsentAnswer(bool granted, Permissions p) => new ProtoWriter().Bool(granted).U8((byte)p).ToArray();
    public static (bool Granted, Permissions Permissions) ParseConsentAnswer(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = (r.Bool(), (Permissions)r.U8());
        r.EnsureEnd();
        return m;
    }

    /// <summary>kind 1 = codec unavailable (fall back to tiles), 0 = generic failure.</summary>
    public static byte[] Error(byte kind, string message) => new ProtoWriter().U8(kind).Str(message.Length > 200 ? message[..200].Replace("\0", "") : message.Replace("\0", "")).ToArray();
    public static (byte Kind, string Message) ParseError(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = (r.U8(), r.Str(256));
        r.EnsureEnd();
        return m;
    }
}

/// <summary>Plain data twin of ConsentRequestInfo (kept separate so the helper protocol has no dependency on Session types' evolution).</summary>
public sealed record HelperConsentInfo(string ViewerName, string Source, bool ViaRelay, Permissions Requested, Permissions Allowed, bool Recording);
