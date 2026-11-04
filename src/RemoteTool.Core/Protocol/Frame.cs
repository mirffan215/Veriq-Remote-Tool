using System.Buffers.Binary;

namespace RemoteTool.Core.Protocol;

public readonly record struct Frame(byte Type, byte[] Payload);

/// <summary>Reads <c>[uint32 length][byte type][payload]</c> frames. Never reads ahead of the current frame.</summary>
public sealed class FrameReader
{
    private readonly Stream _s;
    private readonly Func<byte, bool> _isKnown;
    private long _bytesRead;

    public FrameReader(Stream s, Func<byte, bool> isKnownType, int maxPayload = ProtocolConstants.PreAuthMaxFramePayload)
    {
        _s = s;
        _isKnown = isKnownType;
        MaxPayload = maxPayload;
    }

    /// <summary>Current payload ceiling; raise only after authentication.</summary>
    public int MaxPayload { get; set; }
    public long BytesRead => Interlocked.Read(ref _bytesRead);

    public async ValueTask<Frame> ReadAsync(CancellationToken ct)
    {
        var header = new byte[5];
        await ReadExactAsync(header, ct, allowCleanEof: true).ConfigureAwait(false);
        var len = BinaryPrimitives.ReadUInt32BigEndian(header);
        var type = header[4];
        if (!_isKnown(type)) throw new ProtocolException($"unknown frame type {type}");
        if (len > (uint)MaxPayload) throw new ProtocolException($"frame too large ({len} > {MaxPayload})");
        var payload = len == 0 ? Array.Empty<byte>() : new byte[len];
        if (len > 0) await ReadExactAsync(payload, ct, allowCleanEof: false).ConfigureAwait(false);
        Interlocked.Add(ref _bytesRead, 5 + (long)len);
        return new Frame(type, payload);
    }

    private async ValueTask ReadExactAsync(byte[] buf, CancellationToken ct, bool allowCleanEof)
    {
        var off = 0;
        while (off < buf.Length)
        {
            var n = await _s.ReadAsync(buf.AsMemory(off), ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (off == 0 && allowCleanEof) throw new EndOfStreamException("connection closed");
                throw new ProtocolException("connection closed mid-frame");
            }
            off += n;
        }
    }
}

/// <summary>Thread-safe frame writer (multiple producers: video, cursor, heartbeat).</summary>
public sealed class FrameWriter
{
    private readonly Stream _s;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private long _bytesWritten;

    public FrameWriter(Stream s) { _s = s; }
    public long BytesWritten => Interlocked.Read(ref _bytesWritten);

    public Task WriteAsync(MessageType type, byte[] payload, CancellationToken ct) => WriteAsync((byte)type, payload, ct);
    public Task WriteAsync(RelayMessageType type, byte[] payload, CancellationToken ct) => WriteAsync((byte)type, payload, ct);
    public Task WriteAsync(MessageType type, CancellationToken ct) => WriteAsync((byte)type, Array.Empty<byte>(), ct);
    public Task WriteAsync(RelayMessageType type, CancellationToken ct) => WriteAsync((byte)type, Array.Empty<byte>(), ct);

    public async Task WriteAsync(byte type, byte[] payload, CancellationToken ct)
    {
        if (payload.Length > ProtocolConstants.MaxFramePayload) throw new ProtocolException("payload too large to send");
        var buf = new byte[5 + payload.Length];
        BinaryPrimitives.WriteUInt32BigEndian(buf, (uint)payload.Length);
        buf[4] = type;
        payload.CopyTo(buf, 5);
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await _s.WriteAsync(buf, ct).ConfigureAwait(false);
            await _s.FlushAsync(ct).ConfigureAwait(false);
            Interlocked.Add(ref _bytesWritten, buf.Length);
        }
        finally { _gate.Release(); }
    }
}
