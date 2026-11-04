using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemoteTool.Core.Session;
using Vortice.MediaFoundation;

namespace RemoteTool.Video;

/// <summary>
/// H.264 encoder on Media Foundation. Prefers a hardware MFT (NVENC / Quick Sync / AMF; these are asynchronous), falls back to the
/// built-in Microsoft software MFT (synchronous). Low-latency settings: no B-frames, CBR, long GOP, keyframes on demand.
/// Everything here is Windows-only and could not be executed in the authoring sandbox (docs/DECISIONS.md D-26); any failure surfaces as
/// <see cref="CodecUnavailableException"/> and the host falls back to the tile codec.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class MfH264Encoder : IH264Encoder
{
    private const int MeNeedInput = 601, MeHaveOutput = 602;
    private static readonly object StartupLock = new();
    private static int _startups;

    private readonly IMFTransform _mft;
    private readonly IMFMediaEventGenerator? _events;   // non-null => asynchronous (hardware) MFT
    private readonly ICodecApi? _codec;
    private readonly int _w, _h, _fps;
    private readonly int _outBufferSize;
    private int _needInput;
    private long _frame;
    private int _kbps;
    private byte[]? _sequenceHeader;

    public string Name { get; }
    public bool IsHardware { get; }

    private MfH264Encoder(IMFTransform mft, string name, bool hardware, int w, int h, int fps, int kbps)
    {
        _mft = mft;
        Name = name;
        IsHardware = hardware;
        _w = w; _h = h; _fps = fps; _kbps = kbps;

        // Hardware MFTs are asynchronous and must be explicitly unlocked; the software MFT has no such attribute (or no attribute store at all).
        try
        {
            var attrs = mft.Attributes;
            if (attrs is not null && attrs.GetUInt32(TransformAttributeKeys.TransformAsync, out var isAsync).Success && isAsync == 1)
            {
                attrs.Set(TransformAttributeKeys.TransformAsyncUnlock, 1u);
                _events = mft.QueryInterface<IMFMediaEventGenerator>();
            }
        }
        catch (SharpGen.Runtime.SharpGenException) { _events = null; }
        try { _codec = (ICodecApi)Marshal.GetObjectForIUnknown(mft.NativePointer); } catch (InvalidCastException) { } catch (COMException) { }
        ConfigureCodecApi(kbps);

        using (var outType = MediaFactory.MFCreateMediaType())
        {
            outType.Set(MediaTypeAttributeKeys.MajorType, MediaTypeGuids.Video);
            outType.Set(MediaTypeAttributeKeys.Subtype, MfConst.H264);
            outType.Set(MediaTypeAttributeKeys.AvgBitrate, (uint)(kbps * 1000));
            outType.Set(MediaTypeAttributeKeys.FrameSize, MfConst.Pack(w, h));
            outType.Set(MediaTypeAttributeKeys.FrameRate, MfConst.Pack(fps, 1));
            outType.Set(MediaTypeAttributeKeys.InterlaceMode, 2u);      // progressive
            outType.Set(MediaTypeAttributeKeys.Mpeg2Profile, 66u);      // Baseline: no B-frames, widest decoder support
            mft.SetOutputType(0, outType, 0);
        }
        using (var inType = MediaFactory.MFCreateMediaType())
        {
            inType.Set(MediaTypeAttributeKeys.MajorType, MediaTypeGuids.Video);
            inType.Set(MediaTypeAttributeKeys.Subtype, MfConst.Nv12);
            inType.Set(MediaTypeAttributeKeys.FrameSize, MfConst.Pack(w, h));
            inType.Set(MediaTypeAttributeKeys.FrameRate, MfConst.Pack(fps, 1));
            inType.Set(MediaTypeAttributeKeys.InterlaceMode, 2u);
            mft.SetInputType(0, inType, 0);
        }
        try { _sequenceHeader = mft.GetOutputCurrentType(0).GetBlob(MfConst.MtMpegSequenceHeader); } catch (Exception) { _sequenceHeader = null; }
        _outBufferSize = Math.Max(mft.GetOutputStreamInfo(0).Size, 1 << 20);
        mft.ProcessMessage(TMessageType.MessageCommandFlush, UIntPtr.Zero);
        mft.ProcessMessage(TMessageType.MessageNotifyBeginStreaming, UIntPtr.Zero);
        mft.ProcessMessage(TMessageType.MessageNotifyStartOfStream, UIntPtr.Zero);
    }

    public static IH264Encoder? TryCreate(int width, int height, int fps, int kbps, bool preferHardware, out string? error)
    {
        error = null;
        width &= ~1; height &= ~1;
        EnsureStartup();
        if (preferHardware)
        {
            foreach (var t in EnumerateHardware())
            {
                try { return new MfH264Encoder(t, "Hardware H.264 (Media Foundation)", true, width, height, fps, kbps); }
                catch (Exception e) { error = "hardware encoder rejected: " + e.Message; t.Dispose(); }
            }
        }
        try
        {
            var sw = new IMFTransform(Com.Create(MfConst.ClsidMsH264Encoder, MfConst.IidTransform));
            return new MfH264Encoder(sw, "Software H.264 (Media Foundation)", false, width, height, fps, kbps);
        }
        catch (Exception e) { error = (error is null ? "" : error + "; ") + "software encoder unavailable: " + e.Message; return null; }
    }

    private static void EnsureStartup()
    {
        lock (StartupLock) { if (_startups++ == 0) MediaFactory.MFStartup(false); }
    }

    private static IEnumerable<IMFTransform> EnumerateHardware()
    {
        var found = new List<IMFTransform>();
        IntPtr arr = IntPtr.Zero;
        try
        {
            // MFT_ENUM_FLAG_HARDWARE (4) | MFT_ENUM_FLAG_SORTANDFILTER (0x40)
            var input = new RegisterTypeInfo { GuidMajorType = MediaTypeGuids.Video, GuidSubtype = MfConst.Nv12 };
            var output = new RegisterTypeInfo { GuidMajorType = MediaTypeGuids.Video, GuidSubtype = MfConst.H264 };
            MediaFactory.MFTEnumEx(MfConst.VideoEncoderCategory, 4u | 0x40u, input, output, out arr, out var count);
            for (var i = 0; i < count; i++)
            {
                var p = Marshal.ReadIntPtr(arr, i * IntPtr.Size);
                using var activate = new IMFActivate(p);
                activate.ActivateObject<IMFTransform>(MfConst.IidTransform, out var transform);
                if (transform is not null) found.Add(transform);
            }
        }
        catch (Exception) { /* no hardware MFT, or enumeration failed: caller falls back to software */ }
        finally { if (arr != IntPtr.Zero) Marshal.FreeCoTaskMem(arr); }
        return found;
    }

    private void ConfigureCodecApi(int kbps)
    {
        if (_codec is null) return;
        Set(CodecApiKeys.LowLatency, true);
        Set(CodecApiKeys.RateControlMode, 0u);            // CBR
        Set(CodecApiKeys.MeanBitRate, (uint)(kbps * 1000));
        Set(CodecApiKeys.GopSize, (uint)(_fps * 60));     // keyframes on demand, otherwise one a minute
        Set(CodecApiKeys.BFrames, 0u);
    }

    private void Set(Guid key, object value)
    {
        if (_codec is null) return;
        var v = value;
        var k = key;
        _codec.SetValue(ref k, ref v); // best effort: not every MFT supports every property
    }

    public void SetBitrate(int kbps)
    {
        if (Math.Abs(kbps - _kbps) * 5 < _kbps) return; // ignore <20 % changes
        _kbps = kbps;
        Set(CodecApiKeys.MeanBitRate, (uint)(kbps * 1000));
    }

    public byte[]? Encode(ReadOnlySpan<byte> nv12, bool forceKeyframe)
    {
        try
        {
            if (forceKeyframe) Set(CodecApiKeys.ForceKeyFrame, 1u);
            using var sample = MakeSample(nv12);
            var data = _events is null ? EncodeSync(sample) : EncodeAsync(sample);
            if (data is not null && forceKeyframe && !AnnexB.HasParameterSets(data) && _sequenceHeader is { Length: > 0 })
                data = _sequenceHeader.Concat(data).ToArray(); // make sure a joining viewer can start decoding
            return data;
        }
        catch (CodecUnavailableException) { throw; }
        catch (Exception e) { throw new CodecUnavailableException("H.264 encode failed: " + e.Message, e); }
    }

    private IMFSample MakeSample(ReadOnlySpan<byte> nv12)
    {
        var buffer = MediaFactory.MFCreateMemoryBuffer(nv12.Length);
        buffer.Lock(out var ptr, out _, out _);
        try { nv12.CopyTo(new Span<byte>((void*)ptr, nv12.Length)); }
        finally { buffer.Unlock(); }
        buffer.CurrentLength = nv12.Length;
        var sample = MediaFactory.MFCreateSample();
        sample.AddBuffer(buffer);
        buffer.Dispose();
        var dur = 10_000_000L / _fps;
        sample.SampleTime = _frame++ * dur;
        sample.SampleDuration = dur;
        return sample;
    }

    private byte[]? EncodeSync(IMFSample input)
    {
        _mft.ProcessInput(0, input, 0);
        return DrainOutput();
    }

    private byte[]? EncodeAsync(IMFSample input)
    {
        var deadline = Environment.TickCount64 + 1500;   // a stuck hardware encoder must not stall the session
        var sent = false;
        byte[]? result = null;
        while (Environment.TickCount64 < deadline)
        {
            if (!sent && _needInput > 0) { _needInput--; _mft.ProcessInput(0, input, 0); sent = true; }
            IMFMediaEvent? ev = null;
            try { ev = _events!.GetEvent(1 /* MF_EVENT_FLAG_NO_WAIT */); }
            catch (SharpGen.Runtime.SharpGenException) { Thread.Sleep(1); continue; }  // MF_E_NO_EVENTS_AVAILABLE
            using (ev)
            {
                var type = (int)ev.EventType;
                if (type == MeNeedInput) _needInput++;
                else if (type == MeHaveOutput) { result = DrainOutput(); if (sent && result is not null) return result; }
            }
        }
        throw new CodecUnavailableException("hardware H.264 encoder timed out");
    }

    private byte[]? DrainOutput()
    {
        using var outSample = MediaFactory.MFCreateSample();
        using var outBuffer = MediaFactory.MFCreateMemoryBuffer(_outBufferSize);
        outSample.AddBuffer(outBuffer);
        var odb = new OutputDataBuffer { StreamID = 0, Sample = outSample };
        var hr = _mft.ProcessOutput(ProcessOutputFlags.None, 1, ref odb, out _);
        if (hr.Code == MfConst.ENeedMoreInput) return null;
        hr.CheckError();
        using var contiguous = outSample.ConvertToContiguousBuffer();
        contiguous.Lock(out var ptr, out _, out var len);
        try { return new Span<byte>((void*)ptr, len).ToArray(); }
        finally { contiguous.Unlock(); }
    }

    public void Dispose()
    {
        try { _mft.ProcessMessage(TMessageType.MessageNotifyEndOfStream, UIntPtr.Zero); } catch { }
        _events?.Dispose();
        _mft.Dispose();
        lock (StartupLock) { if (--_startups == 0) MediaFactory.MFShutdown(); }
    }
}
