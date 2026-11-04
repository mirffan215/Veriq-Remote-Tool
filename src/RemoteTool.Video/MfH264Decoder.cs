using System.Runtime.Versioning;
using RemoteTool.Core.Session;
using Vortice.MediaFoundation;

namespace RemoteTool.Video;

/// <summary>
/// Viewer-side H.264 decoder: the built-in Microsoft decoder MFT (software, always present on Windows 11 with the media feature pack),
/// output NV12 converted to BGRA. Windows-only; failures return <see cref="DecodeStatus.Failed"/> so the session falls back to tiles.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class MfH264Decoder : IH264Decoder
{
    private readonly IMFTransform _mft;
    private int _width, _height, _stride;
    private bool _outputReady;
    private long _time;

    public static bool IsSupported()
    {
        try { using var d = Create(); return d is not null; } catch (Exception) { return false; }
    }

    public static MfH264Decoder? Create()
    {
        try { return new MfH264Decoder(); } catch (Exception) { return null; }
    }

    private MfH264Decoder()
    {
        MediaFactory.MFStartup(false);
        _mft = new IMFTransform(Com.Create(MfConst.ClsidMsH264Decoder, MfConst.IidTransform));
        using var inType = MediaFactory.MFCreateMediaType();
        inType.Set(MediaTypeAttributeKeys.MajorType, MediaTypeGuids.Video);
        inType.Set(MediaTypeAttributeKeys.Subtype, MfConst.H264);
        inType.Set(MediaTypeAttributeKeys.InterlaceMode, 2u);
        _mft.SetInputType(0, inType, 0);
        SelectNv12Output();
        _mft.ProcessMessage(TMessageType.MessageNotifyBeginStreaming, UIntPtr.Zero);
        _mft.ProcessMessage(TMessageType.MessageNotifyStartOfStream, UIntPtr.Zero);
    }

    /// <summary>The decoder only offers output types after it has seen the SPS; call again after a stream change.</summary>
    private bool SelectNv12Output()
    {
        for (var i = 0; ; i++)
        {
            IMFMediaType t;
            try { t = _mft.GetOutputAvailableType(0, i); }
            catch (SharpGen.Runtime.SharpGenException) { return false; } // no more types (or none yet)
            using (t)
            {
                if (t.GetGUID(MediaTypeAttributeKeys.Subtype) != MfConst.Nv12) continue;
                _mft.SetOutputType(0, t, 0);
                var size = t.GetUInt64(MediaTypeAttributeKeys.FrameSize);
                _width = (int)(size >> 32);
                _height = (int)(size & 0xFFFFFFFF);
                _stride = t.GetUInt32(MediaTypeAttributeKeys.DefaultStride, out var s).Success && s > 0 ? (int)s : _width;
                _outputReady = true;
                return true;
            }
        }
    }

    public DecodeStatus TryDecode(byte[] annexB, bool keyframe, out DecodedFrame? frame)
    {
        frame = null;
        try
        {
            using var sample = MakeSample(annexB);
            _mft.ProcessInput(0, sample, 0);   // throws on failure
            return Drain(out frame);
        }
        catch (Exception) { return DecodeStatus.Failed; }
    }

    private IMFSample MakeSample(byte[] data)
    {
        var buffer = MediaFactory.MFCreateMemoryBuffer(data.Length);
        buffer.Lock(out var ptr, out _, out _);
        try { data.AsSpan().CopyTo(new Span<byte>((void*)ptr, data.Length)); } finally { buffer.Unlock(); }
        buffer.CurrentLength = data.Length;
        var sample = MediaFactory.MFCreateSample();
        sample.AddBuffer(buffer);
        buffer.Dispose();
        sample.SampleTime = _time;
        sample.SampleDuration = 333_333;
        _time += 333_333;
        return sample;
    }

    private DecodeStatus Drain(out DecodedFrame? frame)
    {
        frame = null;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            if (!_outputReady && !SelectNv12Output()) return DecodeStatus.NeedMoreInput;
            var size = Math.Max(_mft.GetOutputStreamInfo(0).Size, _stride * _height * 3 / 2 + 4096);
            using var outSample = MediaFactory.MFCreateSample();
            using var outBuffer = MediaFactory.MFCreateMemoryBuffer(size);
            outSample.AddBuffer(outBuffer);
            var odb = new OutputDataBuffer { StreamID = 0, Sample = outSample };
            var hr = _mft.ProcessOutput(ProcessOutputFlags.None, 1, ref odb, out _);
            if (hr.Code == MfConst.ENeedMoreInput) return DecodeStatus.NeedMoreInput;
            if (hr.Code == MfConst.EStreamChange) { _outputReady = false; continue; } // resolution change / first SPS
            if (hr.Failure) return DecodeStatus.Failed;
            using var contiguous = outSample.ConvertToContiguousBuffer();
            contiguous.Lock(out var ptr, out _, out var len);
            try
            {
                var nv12 = new Span<byte>((void*)ptr, len).ToArray();
                var planeHeight = Math.Max(_height, len * 2 / 3 / _stride); // some decoders pad the luma plane (e.g. 1088 rows for 1080)
                frame = new DecodedFrame(ColorConvert.Nv12ToBgra(nv12, _stride, _stride * planeHeight, _width, _height), _width, _height);
                return DecodeStatus.Frame;
            }
            finally { contiguous.Unlock(); }
        }
        return DecodeStatus.NeedMoreInput;
    }

    public void Dispose()
    {
        try { _mft.ProcessMessage(TMessageType.MessageNotifyEndOfStream, UIntPtr.Zero); } catch { }
        _mft.Dispose();
        MediaFactory.MFShutdown();
    }
}
