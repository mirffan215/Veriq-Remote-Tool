namespace RemoteTool.Core.Protocol;

public static class ProtocolConstants
{
    public const ushort Version = 1;
    public const int MaxFramePayload = 16 * 1024 * 1024;
    /// <summary>Frame ceiling before authentication completes (bounded allocation for unauthenticated peers).</summary>
    public const int PreAuthMaxFramePayload = 4096;
    public const int NonceLength = 32;
    public const int SaltLength = 16;
    public const int ProofLength = 32;
    /// <summary>Fixed (not negotiable) so a MITM cannot downgrade the work factor.</summary>
    public const int Pbkdf2Iterations = 600_000;
    public const int MaxNameChars = 64;
    public const int MaxMonitors = 16;
    public const int MaxRectsPerFrame = 4096;
    public const int MaxRectJpegBytes = 8 * 1024 * 1024;
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan ConsentTimeout = TimeSpan.FromSeconds(60);
}
