namespace RemoteTool.Core.Protocol;

[Flags]
public enum Permissions : byte
{
    None = 0,
    Control = 1,
    Clipboard = 2,
    FileTransfer = 4,
    All = Control | Clipboard | FileTransfer,
}

public enum AuthFailure : byte
{
    None = 0,
    BadPassword = 1,
    Blocked = 2,
    Busy = 3,
    VersionMismatch = 4,
    NotAllowed = 5,
}

public enum ByeReason : byte
{
    Normal = 0,
    Denied = 1,
    Timeout = 2,
    ProtocolError = 3,
    HostDisconnected = 4,
    Emergency = 5,
}

public enum CursorShape : byte
{
    Arrow = 0, IBeam = 1, Wait = 2, Cross = 3, Hand = 4, SizeNS = 5, SizeWE = 6,
    SizeNWSE = 7, SizeNESW = 8, SizeAll = 9, No = 10, AppStarting = 11, Help = 12, Hidden = 13,
}

public enum MouseKind : byte { Move = 0, Down = 1, Up = 2, Wheel = 3, HWheel = 4 }
public enum MouseButton : byte { None = 0, Left = 1, Right = 2, Middle = 3, X1 = 4, X2 = 5 }

/// <param name="Resume">True when the shared secret is a resume ticket (reconnect after a network drop) instead of the one-time password.</param>
public sealed record HelloMessage(ushort Version, string ViewerName, byte[] Nonce, bool Resume = false)
{
    public byte[] Serialize() => new ProtoWriter().U16(Version).Str(ViewerName).Fixed(Nonce).Bool(Resume).ToArray();

    public static HelloMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new HelloMessage(r.U16(), r.Str(ProtocolConstants.MaxNameChars), r.Fixed(ProtocolConstants.NonceLength), r.Bool());
        r.EnsureEnd();
        return m;
    }
}

public sealed record AuthChallengeMessage(string HostName, byte[] Nonce, byte[] Salt)
{
    public byte[] Serialize() => new ProtoWriter().Str(HostName).Fixed(Nonce).Fixed(Salt).ToArray();

    public static AuthChallengeMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new AuthChallengeMessage(r.Str(ProtocolConstants.MaxNameChars), r.Fixed(ProtocolConstants.NonceLength), r.Fixed(ProtocolConstants.SaltLength));
        r.EnsureEnd();
        return m;
    }
}

public sealed record AuthResponseMessage(byte[] Proof)
{
    public byte[] Serialize() => new ProtoWriter().Fixed(Proof).ToArray();

    public static AuthResponseMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new AuthResponseMessage(r.Fixed(ProtocolConstants.ProofLength));
        r.EnsureEnd();
        return m;
    }
}

public sealed record AuthResultMessage(bool Success, AuthFailure Failure, byte[] HostProof)
{
    public byte[] Serialize() => new ProtoWriter().Bool(Success).U8((byte)Failure).Fixed(HostProof).ToArray();

    public static AuthResultMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var ok = r.Bool();
        var f = r.U8();
        if (f > (byte)AuthFailure.NotAllowed) throw new ProtocolException("invalid auth failure code");
        var m = new AuthResultMessage(ok, (AuthFailure)f, r.Fixed(ProtocolConstants.ProofLength));
        r.EnsureEnd();
        return m;
    }
}

public sealed record ConsentRequestMessage(Permissions Requested)
{
    public byte[] Serialize() => new ProtoWriter().U8((byte)Requested).ToArray();

    public static ConsentRequestMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new ConsentRequestMessage(ParsePermissions(r.U8()));
        r.EnsureEnd();
        return m;
    }

    internal static Permissions ParsePermissions(byte b)
    {
        if ((b & ~(byte)Permissions.All) != 0) throw new ProtocolException("invalid permission bits");
        return (Permissions)b;
    }
}

/// <param name="ResumeToken">High-entropy single-use ticket (ASCII hex) the viewer can use to resume after a network drop; empty when denied.</param>
public sealed record ConsentResultMessage(bool Granted, Permissions GrantedPermissions, ByeReason DenyReason, byte[]? ResumeToken = null)
{
    public byte[] Serialize() => new ProtoWriter().Bool(Granted).U8((byte)GrantedPermissions).U8((byte)DenyReason).Bytes(ResumeToken ?? Array.Empty<byte>()).ToArray();

    public static ConsentResultMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var g = r.Bool();
        var perms = ConsentRequestMessage.ParsePermissions(r.U8());
        var reason = r.U8();
        if (reason > (byte)ByeReason.Emergency) throw new ProtocolException("invalid reason");
        var token = r.Bytes(64);
        r.EnsureEnd();
        return new ConsentResultMessage(g, perms, (ByeReason)reason, token);
    }
}

public sealed record MonitorInfo(byte Index, int X, int Y, int Width, int Height, bool Primary, string Name);

public sealed record ScreenInfoMessage(IReadOnlyList<MonitorInfo> Monitors, byte ActiveMonitor)
{
    public byte[] Serialize()
    {
        var w = new ProtoWriter().U8((byte)Monitors.Count).U8(ActiveMonitor);
        foreach (var m in Monitors)
            w.U8(m.Index).I32(m.X).I32(m.Y).I32(m.Width).I32(m.Height).Bool(m.Primary).Str(m.Name);
        return w.ToArray();
    }

    public static ScreenInfoMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var count = r.U8();
        var active = r.U8();
        if (count == 0 || count > ProtocolConstants.MaxMonitors) throw new ProtocolException("invalid monitor count");
        var list = new List<MonitorInfo>(count);
        for (var i = 0; i < count; i++)
        {
            var m = new MonitorInfo(r.U8(), r.I32(), r.I32(), r.I32(), r.I32(), r.Bool(), r.Str(32));
            if (m.Width is <= 0 or > 65535 || m.Height is <= 0 or > 65535) throw new ProtocolException("invalid monitor size");
            list.Add(m);
        }
        if (active >= count) throw new ProtocolException("invalid active monitor");
        r.EnsureEnd();
        return new ScreenInfoMessage(list, active);
    }
}

public sealed record TileRect(int X, int Y, int Width, int Height, byte[] Jpeg);

public sealed record FrameUpdateMessage(byte MonitorIndex, uint Sequence, int Width, int Height, bool Keyframe, IReadOnlyList<TileRect> Rects)
{
    public byte[] Serialize()
    {
        var w = new ProtoWriter().U8(MonitorIndex).U32(Sequence).U16((ushort)Width).U16((ushort)Height).Bool(Keyframe).U16((ushort)Rects.Count);
        foreach (var t in Rects) w.U16((ushort)t.X).U16((ushort)t.Y).U16((ushort)t.Width).U16((ushort)t.Height).Bytes(t.Jpeg);
        return w.ToArray();
    }

    public static FrameUpdateMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var mon = r.U8();
        var seq = r.U32();
        int w = r.U16(), h = r.U16();
        var key = r.Bool();
        int n = r.U16();
        if (w == 0 || h == 0) throw new ProtocolException("invalid frame size");
        if (n > ProtocolConstants.MaxRectsPerFrame) throw new ProtocolException("too many rects");
        var rects = new List<TileRect>(n);
        for (var i = 0; i < n; i++)
        {
            int x = r.U16(), y = r.U16(), rw = r.U16(), rh = r.U16();
            if (rw == 0 || rh == 0 || x + rw > w || y + rh > h) throw new ProtocolException("rect outside frame");
            rects.Add(new TileRect(x, y, rw, rh, r.Bytes(ProtocolConstants.MaxRectJpegBytes)));
        }
        r.EnsureEnd();
        return new FrameUpdateMessage(mon, seq, w, h, key, rects);
    }
}

public sealed record CursorUpdateMessage(CursorShape Shape)
{
    public byte[] Serialize() => new ProtoWriter().U8((byte)Shape).ToArray();

    public static CursorUpdateMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var s = r.U8();
        if (s > (byte)CursorShape.Hidden) throw new ProtocolException("invalid cursor shape");
        r.EnsureEnd();
        return new CursorUpdateMessage((CursorShape)s);
    }
}

/// <summary>Coordinates are normalized 0..65535 across the selected monitor.</summary>
public sealed record MouseEventMessage(MouseKind Kind, MouseButton Button, ushort X, ushort Y, int WheelDelta)
{
    public byte[] Serialize() => new ProtoWriter().U8((byte)Kind).U8((byte)Button).U16(X).U16(Y).I32(WheelDelta).ToArray();

    public static MouseEventMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var k = r.U8();
        var b = r.U8();
        if (k > (byte)MouseKind.HWheel || b > (byte)MouseButton.X2) throw new ProtocolException("invalid mouse event");
        var m = new MouseEventMessage((MouseKind)k, (MouseButton)b, r.U16(), r.U16(), r.I32());
        r.EnsureEnd();
        if (m.Kind is MouseKind.Down or MouseKind.Up && m.Button == MouseButton.None) throw new ProtocolException("button required");
        if (Math.Abs((long)m.WheelDelta) > 120 * 100) throw new ProtocolException("wheel delta out of range");
        return m;
    }
}

public sealed record KeyEventMessage(ushort VirtualKey, bool KeyUp, bool Extended)
{
    public byte[] Serialize() => new ProtoWriter().U16(VirtualKey).U8((byte)((KeyUp ? 1 : 0) | (Extended ? 2 : 0))).ToArray();

    public static KeyEventMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var vk = r.U16();
        var f = r.U8();
        if (vk is 0 or > 254 || (f & ~3) != 0) throw new ProtocolException("invalid key event");
        r.EnsureEnd();
        return new KeyEventMessage(vk, (f & 1) != 0, (f & 2) != 0);
    }
}

public sealed record PingMessage(ulong Ticks)
{
    public byte[] Serialize() => new ProtoWriter().U64(Ticks).ToArray();

    public static PingMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new PingMessage(r.U64());
        r.EnsureEnd();
        return m;
    }
}

public sealed record ByeMessage(ByeReason Reason, string Text)
{
    public byte[] Serialize() => new ProtoWriter().U8((byte)Reason).Str(Text).ToArray();

    public static ByeMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var reason = r.U8();
        if (reason > (byte)ByeReason.Emergency) throw new ProtocolException("invalid bye reason");
        var m = new ByeMessage((ByeReason)reason, r.Str(128));
        r.EnsureEnd();
        return m;
    }
}

public sealed record MonitorSelectMessage(byte Index)
{
    public byte[] Serialize() => new ProtoWriter().U8(Index).ToArray();

    public static MonitorSelectMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new MonitorSelectMessage(r.U8());
        r.EnsureEnd();
        if (m.Index >= ProtocolConstants.MaxMonitors) throw new ProtocolException("invalid monitor");
        return m;
    }
}

/// <summary>Plain UTF-8 text (the only clipboard format in v1). Newlines/tabs allowed, size capped.</summary>
public sealed record ClipboardDataMessage(string Text)
{
    private static readonly System.Text.UTF8Encoding Utf8 = new(false, true);

    public byte[] Serialize()
    {
        var bytes = Utf8.GetBytes(Text);
        if (bytes.Length > ProtocolConstants.MaxClipboardBytes) throw new ProtocolException("clipboard too large");
        return new ProtoWriter().U8(0).Bytes(bytes).ToArray();
    }

    public static ClipboardDataMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        if (r.U8() != 0) throw new ProtocolException("unsupported clipboard format");
        var raw = r.Bytes(ProtocolConstants.MaxClipboardBytes);
        r.EnsureEnd();
        try { return new ClipboardDataMessage(Utf8.GetString(raw)); }
        catch (System.Text.DecoderFallbackException e) { throw new ProtocolException("invalid UTF-8", e); }
    }
}

public enum FileStatus : byte { Accept = 0, Reject = 1, Complete = 2, HashMismatch = 3, Error = 4, Cancel = 5 }

public sealed record FileOfferMessage(uint TransferId, string Name, ulong Size, byte[] Sha256)
{
    public byte[] Serialize() => new ProtoWriter().U32(TransferId).Str(Name).U64(Size).Fixed(Sha256).ToArray();

    public static FileOfferMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new FileOfferMessage(r.U32(), r.Str(ProtocolConstants.MaxFileNameChars), r.U64(), r.Fixed(32));
        r.EnsureEnd();
        return m;
    }
}

public sealed record FileChunkMessage(uint TransferId, ulong Offset, byte[] Data)
{
    public byte[] Serialize() => new ProtoWriter().U32(TransferId).U64(Offset).Bytes(Data).ToArray();

    public static FileChunkMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new FileChunkMessage(r.U32(), r.U64(), r.Bytes(ProtocolConstants.MaxFileChunk));
        r.EnsureEnd();
        return m;
    }
}

public sealed record FileAckMessage(uint TransferId, FileStatus Status, ulong Received)
{
    public byte[] Serialize() => new ProtoWriter().U32(TransferId).U8((byte)Status).U64(Received).ToArray();

    public static FileAckMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var id = r.U32();
        var st = r.U8();
        if (st > (byte)FileStatus.Cancel) throw new ProtocolException("invalid file status");
        var m = new FileAckMessage(id, (FileStatus)st, r.U64());
        r.EnsureEnd();
        return m;
    }
}
