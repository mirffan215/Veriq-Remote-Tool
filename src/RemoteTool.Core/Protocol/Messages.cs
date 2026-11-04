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

public enum AuthMode : byte
{
    /// <summary>Secret = the one-time password shown on the host.</summary>
    OneTimePassword = 0,
    /// <summary>Secret = resume ticket from a previous session (reconnect after a network drop).</summary>
    Resume = 1,
    /// <summary>Secret = the permanent (unattended) password; only accepted when the host runs the service with unattended access enabled.</summary>
    Permanent = 2,
}

[Flags]
public enum VideoCodecs : byte { None = 0, TileJpeg = 1, H264 = 2 }

/// <param name="Mode">Which secret the viewer proves knowledge of.</param>
public sealed record HelloMessage(ushort Version, string ViewerName, byte[] Nonce, AuthMode Mode = AuthMode.OneTimePassword)
{
    public bool Resume => Mode == AuthMode.Resume;

    public byte[] Serialize() => new ProtoWriter().U16(Version).Str(ViewerName).Fixed(Nonce).U8((byte)Mode).ToArray();

    public static HelloMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var ver = r.U16();
        var name = r.Str(ProtocolConstants.MaxNameChars);
        var nonce = r.Fixed(ProtocolConstants.NonceLength);
        var mode = r.U8();
        if (mode > (byte)AuthMode.Permanent) throw new ProtocolException("invalid auth mode");
        r.EnsureEnd();
        return new HelloMessage(ver, name, nonce, (AuthMode)mode);
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

public sealed record ConsentRequestMessage(Permissions Requested, VideoCodecs Codecs = VideoCodecs.TileJpeg)
{
    public byte[] Serialize() => new ProtoWriter().U8((byte)Requested).U8((byte)Codecs).ToArray();

    public static ConsentRequestMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var perms = ParsePermissions(r.U8());
        var codecs = r.U8();
        if ((codecs & ~3) != 0 || (codecs & 1) == 0) throw new ProtocolException("invalid codec set (tile codec is mandatory)");
        r.EnsureEnd();
        return new ConsentRequestMessage(perms, (VideoCodecs)codecs);
    }

    internal static Permissions ParsePermissions(byte b)
    {
        if ((b & ~(byte)Permissions.All) != 0) throw new ProtocolException("invalid permission bits");
        return (Permissions)b;
    }
}

/// <param name="ResumeToken">High-entropy single-use ticket (ASCII hex) the viewer can use to resume after a network drop; empty when denied.</param>
/// <param name="Codec">The single codec the host will start the video stream with.</param>
/// <param name="Recording">True when the host records this session (the viewer must show a REC indicator).</param>
public sealed record ConsentResultMessage(bool Granted, Permissions GrantedPermissions, ByeReason DenyReason, byte[]? ResumeToken = null,
    VideoCodecs Codec = VideoCodecs.TileJpeg, bool Recording = false)
{
    public byte[] Serialize() => new ProtoWriter().Bool(Granted).U8((byte)GrantedPermissions).U8((byte)DenyReason).Bytes(ResumeToken ?? Array.Empty<byte>())
        .U8((byte)Codec).Bool(Recording).ToArray();

    public static ConsentResultMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var g = r.Bool();
        var perms = ConsentRequestMessage.ParsePermissions(r.U8());
        var reason = r.U8();
        if (reason > (byte)ByeReason.Emergency) throw new ProtocolException("invalid reason");
        var token = r.Bytes(64);
        var codec = r.U8();
        if (codec is not (1 or 2)) throw new ProtocolException("invalid codec");
        var rec = r.Bool();
        r.EnsureEnd();
        return new ConsentResultMessage(g, perms, (ByeReason)reason, token, (VideoCodecs)codec, rec);
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

public enum SpecialKeyKind : byte { CtrlAltDel = 0 }

/// <summary>Key combinations the viewer cannot inject with ordinary input (needs the service: SendSAS).</summary>
public sealed record SpecialKeyMessage(SpecialKeyKind Kind)
{
    public byte[] Serialize() => new ProtoWriter().U8((byte)Kind).ToArray();

    public static SpecialKeyMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var k = r.U8();
        if (k > (byte)SpecialKeyKind.CtrlAltDel) throw new ProtocolException("invalid special key");
        r.EnsureEnd();
        return new SpecialKeyMessage((SpecialKeyKind)k);
    }
}

/// <summary>One H.264 access unit (Annex B). The first frame after (re)start of the codec is always a keyframe with SPS/PPS.</summary>
public sealed record VideoFrameMessage(byte MonitorIndex, uint Sequence, int Width, int Height, bool Keyframe, byte[] Data)
{
    public byte[] Serialize() => new ProtoWriter().U8(MonitorIndex).U32(Sequence).U16((ushort)Width).U16((ushort)Height).Bool(Keyframe).Bytes(Data).ToArray();

    public static VideoFrameMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new VideoFrameMessage(r.U8(), r.U32(), r.U16(), r.U16(), r.Bool(), Array.Empty<byte>());
        if (m.Width == 0 || m.Height == 0) throw new ProtocolException("invalid frame size");
        var data = r.Bytes(ProtocolConstants.MaxRectJpegBytes);
        r.EnsureEnd();
        return m with { Data = data };
    }
}

/// <summary>
/// "From now on use this codec." Host→viewer announces a switch (fallback after an encoder failure); viewer→host asks for the tile codec
/// when its decoder fails. The next frame after a switch is always a keyframe.
/// </summary>
public sealed record CodecSwitchMessage(VideoCodecs Codec)
{
    public byte[] Serialize() => new ProtoWriter().U8((byte)Codec).ToArray();

    public static CodecSwitchMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var c = r.U8();
        if (c is not (1 or 2)) throw new ProtocolException("invalid codec");
        r.EnsureEnd();
        return new CodecSwitchMessage((VideoCodecs)c);
    }
}
