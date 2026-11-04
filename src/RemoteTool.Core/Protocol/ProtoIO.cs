using System.Buffers.Binary;
using System.Text;

namespace RemoteTool.Core.Protocol;

/// <summary>Big-endian payload writer.</summary>
public sealed class ProtoWriter
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly MemoryStream _ms = new();

    public ProtoWriter U8(byte v) { _ms.WriteByte(v); return this; }
    public ProtoWriter Bool(bool v) => U8(v ? (byte)1 : (byte)0);
    public ProtoWriter U16(ushort v) { Span<byte> b = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, v); _ms.Write(b); return this; }
    public ProtoWriter U32(uint v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); _ms.Write(b); return this; }
    public ProtoWriter I32(int v) { Span<byte> b = stackalloc byte[4]; BinaryPrimitives.WriteInt32BigEndian(b, v); _ms.Write(b); return this; }
    public ProtoWriter U64(ulong v) { Span<byte> b = stackalloc byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, v); _ms.Write(b); return this; }
    public ProtoWriter Fixed(ReadOnlySpan<byte> v) { _ms.Write(v); return this; }
    public ProtoWriter Bytes(ReadOnlySpan<byte> v) { U32((uint)v.Length); _ms.Write(v); return this; }

    public ProtoWriter Str(string v)
    {
        var bytes = Utf8.GetBytes(v);
        if (bytes.Length > ushort.MaxValue) throw new ProtocolException("string too long");
        U16((ushort)bytes.Length);
        _ms.Write(bytes);
        return this;
    }

    public byte[] ToArray() => _ms.ToArray();
}

/// <summary>Bounds-checked big-endian payload reader. Every failure is a <see cref="ProtocolException"/>.</summary>
public sealed class ProtoReader
{
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly ReadOnlyMemory<byte> _buf;
    private int _pos;

    public ProtoReader(ReadOnlyMemory<byte> buf) { _buf = buf; }
    public int Remaining => _buf.Length - _pos;

    private ReadOnlySpan<byte> Take(int n)
    {
        if (n < 0 || n > Remaining) throw new ProtocolException("truncated payload");
        var s = _buf.Span.Slice(_pos, n);
        _pos += n;
        return s;
    }

    public byte U8() => Take(1)[0];

    public bool Bool()
    {
        var v = U8();
        if (v > 1) throw new ProtocolException("invalid boolean");
        return v == 1;
    }

    public ushort U16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));
    public uint U32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));
    public int I32() => BinaryPrimitives.ReadInt32BigEndian(Take(4));
    public ulong U64() => BinaryPrimitives.ReadUInt64BigEndian(Take(8));
    public byte[] Fixed(int n) => Take(n).ToArray();

    public byte[] Bytes(int maxLen)
    {
        var len = U32();
        if (len > (uint)maxLen || len > (uint)Remaining) throw new ProtocolException("byte field too long");
        return Take((int)len).ToArray();
    }

    public string Str(int maxChars)
    {
        var len = U16();
        var raw = Take(len);
        try
        {
            var s = Utf8.GetString(raw);
            if (s.Length > maxChars) throw new ProtocolException("string too long");
            foreach (var c in s)
                if (char.IsControl(c)) throw new ProtocolException("control character in string");
            return s;
        }
        catch (DecoderFallbackException e) { throw new ProtocolException("invalid UTF-8", e); }
    }

    public void EnsureEnd()
    {
        if (Remaining != 0) throw new ProtocolException("trailing bytes in payload");
    }
}
