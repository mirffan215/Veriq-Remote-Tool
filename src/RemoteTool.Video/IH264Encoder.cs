namespace RemoteTool.Video;

/// <summary>NV12 in, Annex-B H.264 out (SPS/PPS included on every keyframe).</summary>
public interface IH264Encoder : IDisposable
{
    string Name { get; }
    bool IsHardware { get; }
    void SetBitrate(int kbps);
    /// <summary>Returns null while the encoder is still buffering. Throws <see cref="RemoteTool.Core.Session.CodecUnavailableException"/> if it is broken.</summary>
    byte[]? Encode(ReadOnlySpan<byte> nv12, bool forceKeyframe);
}
