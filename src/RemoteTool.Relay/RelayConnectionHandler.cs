using System.Net;
using Microsoft.AspNetCore.Connections;

namespace RemoteTool.Relay;

/// <summary>Kestrel raw-TCP endpoint: hands the (already TLS-terminated) byte stream to the relay engine.</summary>
public sealed class RelayConnectionHandler : ConnectionHandler
{
    private readonly RelayEngine _engine;
    public RelayConnectionHandler(RelayEngine engine) { _engine = engine; }

    public override async Task OnConnectedAsync(ConnectionContext connection)
    {
        var ip = (connection.RemoteEndPoint as IPEndPoint)?.Address ?? IPAddress.None;
        await using var stream = new DuplexPipeStream(connection.Transport);
        await _engine.HandleAsync(stream, ip, connection.ConnectionClosed).ConfigureAwait(false);
    }
}

internal sealed class DuplexPipeStream : Stream
{
    private readonly Stream _in, _out;
    public DuplexPipeStream(System.IO.Pipelines.IDuplexPipe pipe) { _in = pipe.Input.AsStream(); _out = pipe.Output.AsStream(); }
    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _out.Flush();
    public override Task FlushAsync(CancellationToken ct) => _out.FlushAsync(ct);
    public override int Read(byte[] b, int o, int c) => _in.Read(b, o, c);
    public override ValueTask<int> ReadAsync(Memory<byte> m, CancellationToken ct = default) => _in.ReadAsync(m, ct);
    public override void Write(byte[] b, int o, int c) => _out.Write(b, o, c);
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> m, CancellationToken ct = default) => _out.WriteAsync(m, ct);
    public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
    public override void SetLength(long v) => throw new NotSupportedException();
}
