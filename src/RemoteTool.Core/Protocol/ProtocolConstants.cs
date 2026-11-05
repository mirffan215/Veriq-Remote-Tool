namespace RemoteTool.Core.Protocol;

public static class ProtocolConstants
{
    public const ushort Version = 3;
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
    /// <summary>Largest surface a peer may announce (8K = 33 MP; this allows 8192x8192). Bounds the viewer's bitmap and decode buffers against hostile hosts.</summary>
    public const long MaxFramePixels = 8192L * 8192;
    public const int MaxClipboardBytes = 1024 * 1024;
    public const int DefaultFileChunk = 64 * 1024;
    public const int MaxFileChunk = 256 * 1024;
    public const int MaxFileNameChars = 255;
    public static readonly TimeSpan ResumeWindow = TimeSpan.FromMinutes(2);
    public const int MaxRectsPerFrame = 4096;
    public const int MaxRectJpegBytes = 8 * 1024 * 1024;
    public static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan HeartbeatTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan ConsentTimeout = TimeSpan.FromSeconds(60);
}
