using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace RemoteTool.Video;

/// <summary>Minimal ICodecAPI (Vortice does not wrap it): only the members up to SetValue, in vtable order.</summary>
[ComImport, Guid("901db4c7-31ce-41a2-85dc-8fa0bf41b8da"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
[SupportedOSPlatform("windows")]
internal interface ICodecApi
{
    [PreserveSig] int IsSupported(ref Guid api);
    [PreserveSig] int IsModifiable(ref Guid api);
    [PreserveSig] int GetParameterRange(ref Guid api, out object min, out object max, out object step);
    [PreserveSig] int GetParameterValues(ref Guid api, out IntPtr values, out uint count);
    [PreserveSig] int GetDefaultValue(ref Guid api, out object value);
    [PreserveSig] int GetValue(ref Guid api, out object value);
    [PreserveSig] int SetValue(ref Guid api, [In, MarshalAs(UnmanagedType.Struct)] ref object value);
}

internal static class CodecApiKeys
{
    public static readonly Guid ForceKeyFrame = new("398c1b98-8353-475a-9ef2-8f265d260345");
    public static readonly Guid LowLatency = new("9c27891a-ed7a-40e1-88e8-b22727a024ee");
    public static readonly Guid RateControlMode = new("1c0608e9-370c-4710-8a58-cb6181c42423");
    public static readonly Guid MeanBitRate = new("f7222374-2144-4815-b550-a37f8e12ee52");
    public static readonly Guid GopSize = new("95f31b26-95a4-41aa-9303-246a7fc6eef1");
    public static readonly Guid BFrames = new("8d390aac-dc5c-4200-b57f-814d04babab2");
}

internal static class MfConst
{
    public const uint MfVersion = 0x00020070;
    public static readonly Guid ClsidMsH264Encoder = new("6ca50344-051a-4ded-9779-a43305165e35");
    public static readonly Guid ClsidMsH264Decoder = new("62ce7e72-4c71-4d20-b15d-452831a87d9d");
    public static readonly Guid IidTransform = new("bf94c121-5b05-4e6f-8000-ba598961414d");
    public static readonly Guid VideoEncoderCategory = new("f79eac7d-e545-4387-bdee-d647d7bde42a");
    public static readonly Guid Nv12 = new("3231564e-0000-0010-8000-00aa00389b71");
    public static readonly Guid H264 = new("34363248-0000-0010-8000-00aa00389b71");
    public static readonly Guid MtMpegSequenceHeader = new("3c036de7-3ad0-4c9e-9216-ee6d6fb1da9f"); // MF_MT_MPEG_SEQUENCE_HEADER
    public const int ENeedMoreInput = unchecked((int)0xC00D6D72);
    public const int EStreamChange = unchecked((int)0xC00D6D61);
    public const int ENotAccepting = unchecked((int)0xC00D36B5);

    public static ulong Pack(int hi, int lo) => ((ulong)(uint)hi << 32) | (uint)lo;
}

internal static class Com
{
    [DllImport("ole32.dll")] private static extern int CoCreateInstance(ref Guid clsid, IntPtr outer, uint context, ref Guid iid, out IntPtr obj);
    [DllImport("ole32.dll")] private static extern int CoInitializeEx(IntPtr reserved, uint flags);

    public static IntPtr Create(Guid clsid, Guid iid)
    {
        CoInitializeEx(IntPtr.Zero, 0x0 /* COINIT_MULTITHREADED */);
        var hr = CoCreateInstance(ref clsid, IntPtr.Zero, 1 /* CLSCTX_INPROC_SERVER */, ref iid, out var p);
        if (hr < 0) throw new COMException("CoCreateInstance failed", hr);
        return p;
    }
}
