using System.Buffers.Binary;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Tests;

public class FramingTests
{
    private static FrameReader Reader(byte[] data, int max = 4096) => new(new MemoryStream(data), MessageTypes.IsKnownPeer, max);

    [Fact]
    public async Task RoundTrip()
    {
        var ms = new MemoryStream();
        await new FrameWriter(ms).WriteAsync(MessageType.Ping, new PingMessage(42).Serialize(), default);
        ms.Position = 0;
        var f = await new FrameReader(ms, MessageTypes.IsKnownPeer).ReadAsync(default);
        Assert.Equal((byte)MessageType.Ping, f.Type);
        Assert.Equal(42UL, PingMessage.Parse(f.Payload).Ticks);
    }

    [Fact]
    public async Task RejectsUnknownType()
    {
        var data = new byte[] { 0, 0, 0, 0, 99 };
        await Assert.ThrowsAsync<ProtocolException>(async () => await Reader(data).ReadAsync(default));
    }

    [Fact]
    public async Task RejectsOversizedFrameBeforeAllocating()
    {
        var data = new byte[5];
        BinaryPrimitives.WriteUInt32BigEndian(data, uint.MaxValue);
        data[4] = (byte)MessageType.Ping;
        await Assert.ThrowsAsync<ProtocolException>(async () => await Reader(data).ReadAsync(default));
    }

    [Fact]
    public async Task TruncatedPayloadIsProtocolError()
    {
        var data = new byte[] { 0, 0, 0, 10, (byte)MessageType.Ping, 1, 2 };
        await Assert.ThrowsAsync<ProtocolException>(async () => await Reader(data).ReadAsync(default));
    }

    [Fact]
    public async Task CleanEofIsEndOfStream()
        => await Assert.ThrowsAsync<EndOfStreamException>(async () => await Reader(Array.Empty<byte>()).ReadAsync(default));

    [Fact]
    public async Task FuzzedStreamsOnlyFailWithExpectedExceptions()
    {
        var rng = new Random(1234);
        for (var i = 0; i < 3000; i++)
        {
            var data = new byte[rng.Next(0, 200)];
            rng.NextBytes(data);
            var r = Reader(data, 1024);
            try
            {
                while (true)
                {
                    var f = await r.ReadAsync(default);
                    Parse(f); // every parser must also fail only with ProtocolException
                }
            }
            catch (EndOfStreamException) { }
            catch (ProtocolException) { }
        }
    }

    [Fact]
    public void FuzzedPayloadsNeverCrashParsers()
    {
        var rng = new Random(99);
        for (var i = 0; i < 20000; i++)
        {
            var data = new byte[rng.Next(0, 80)];
            rng.NextBytes(data);
            for (byte t = 1; t <= 19; t++)
            {
                try { Parse(new Frame(t, data)); } catch (ProtocolException) { }
            }
        }
    }

    private static void Parse(Frame f)
    {
        switch ((MessageType)f.Type)
        {
            case MessageType.Hello: HelloMessage.Parse(f.Payload); break;
            case MessageType.AuthChallenge: AuthChallengeMessage.Parse(f.Payload); break;
            case MessageType.AuthResponse: AuthResponseMessage.Parse(f.Payload); break;
            case MessageType.AuthResult: AuthResultMessage.Parse(f.Payload); break;
            case MessageType.ConsentRequest: ConsentRequestMessage.Parse(f.Payload); break;
            case MessageType.ConsentResult: ConsentResultMessage.Parse(f.Payload); break;
            case MessageType.ScreenInfo: ScreenInfoMessage.Parse(f.Payload); break;
            case MessageType.FrameUpdate: FrameUpdateMessage.Parse(f.Payload); break;
            case MessageType.CursorUpdate: CursorUpdateMessage.Parse(f.Payload); break;
            case MessageType.MouseEvent: MouseEventMessage.Parse(f.Payload); break;
            case MessageType.KeyEvent: KeyEventMessage.Parse(f.Payload); break;
            case MessageType.Ping or MessageType.Pong: PingMessage.Parse(f.Payload); break;
            case MessageType.Bye: ByeMessage.Parse(f.Payload); break;
            case MessageType.MonitorSelect: MonitorSelectMessage.Parse(f.Payload); break;
            case MessageType.ClipboardData: ClipboardDataMessage.Parse(f.Payload); break;
            case MessageType.FileOffer: FileOfferMessage.Parse(f.Payload); break;
            case MessageType.FileChunk: FileChunkMessage.Parse(f.Payload); break;
            case MessageType.FileAck: FileAckMessage.Parse(f.Payload); break;
        }
    }

    [Fact]
    public void FrameUpdateRejectsRectOutsideFrame()
    {
        var bad = new FrameUpdateMessage(0, 1, 64, 64, true, new[] { new TileRect(60, 0, 10, 10, new byte[1]) }).Serialize();
        Assert.Throws<ProtocolException>(() => FrameUpdateMessage.Parse(bad));
    }

    [Fact]
    public void MessagesRoundTrip()
    {
        var f = new FrameUpdateMessage(1, 7, 100, 80, false, new[] { new TileRect(1, 2, 3, 4, new byte[] { 9, 9 }) });
        var p = FrameUpdateMessage.Parse(f.Serialize());
        Assert.Equal(7u, p.Sequence);
        Assert.Equal(new byte[] { 9, 9 }, p.Rects[0].Jpeg);
        var m = MouseEventMessage.Parse(new MouseEventMessage(MouseKind.Down, MouseButton.Left, 100, 200, 0).Serialize());
        Assert.Equal((ushort)200, m.Y);
        Assert.Throws<ProtocolException>(() => MouseEventMessage.Parse(new MouseEventMessage(MouseKind.Down, MouseButton.None, 1, 1, 0).Serialize()));
        Assert.Throws<ProtocolException>(() => KeyEventMessage.Parse(new KeyEventMessage(0, false, false).Serialize()));
    }

    [Fact]
    public void StringsRejectControlCharactersAndTrailingBytes()
    {
        var bad = new ProtoWriter().U16(1).Str("evil\u0007name").Fixed(new byte[32]).ToArray();
        Assert.Throws<ProtocolException>(() => HelloMessage.Parse(bad));
        var trailing = new ProtoWriter().U64(1).U8(0).ToArray();
        Assert.Throws<ProtocolException>(() => PingMessage.Parse(trailing));
    }
}
