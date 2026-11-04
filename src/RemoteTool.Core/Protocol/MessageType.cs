namespace RemoteTool.Core.Protocol;

/// <summary>Peer-to-peer message types (end-to-end encrypted channel). Values are part of the wire format.</summary>
public enum MessageType : byte
{
    Hello = 1,
    AuthChallenge = 2,
    AuthResponse = 3,
    AuthResult = 4,
    ConsentRequest = 5,
    ConsentResult = 6,
    ScreenInfo = 7,
    FrameUpdate = 8,
    CursorUpdate = 9,
    MouseEvent = 10,
    KeyEvent = 11,
    ClipboardData = 12,
    FileOffer = 13,
    FileChunk = 14,
    FileAck = 15,
    Ping = 16,
    Pong = 17,
    Bye = 18,
    MonitorSelect = 19,
    SpecialKey = 20,
    VideoFrame = 21,
    CodecSwitch = 22,
}

/// <summary>Relay control message types (outer TLS link to the relay). Disjoint range from <see cref="MessageType"/>.</summary>
public enum RelayMessageType : byte
{
    Register = 0x80,
    Registered = 0x81,
    IdTaken = 0x82,
    Denied = 0x83,
    Incoming = 0x84,
    Accept = 0x85,
    Connect = 0x86,
    Ready = 0x87,
    NotFound = 0x88,
    RelayPing = 0x89,
    RelayPong = 0x8A,
}

public static class MessageTypes
{
    public static bool IsKnownPeer(byte t) => t is >= 1 and <= 22;
    public static bool IsKnownRelay(byte t) => t is >= 0x80 and <= 0x8A;
}
