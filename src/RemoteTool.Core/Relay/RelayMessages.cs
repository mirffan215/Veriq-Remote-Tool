using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Relay;

public static class RelayLimits
{
    public const int MaxControlPayload = 512;
    public const int TokenLength = 16;
    public const int InstanceIdLength = 16;
    public const int MaxAccessKeyChars = 128;
}

public sealed record RegisterMessage(string AccessKey, string Id, byte[] InstanceId)
{
    public byte[] Serialize() => new ProtoWriter().U16(ProtocolConstants.Version).Str(AccessKey).Str(Id).Fixed(InstanceId).ToArray();

    public static RegisterMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        if (r.U16() != ProtocolConstants.Version) throw new ProtocolException("version mismatch");
        var m = new RegisterMessage(r.Str(RelayLimits.MaxAccessKeyChars), r.Str(Config.ConnectionId.MaxLength), r.Fixed(RelayLimits.InstanceIdLength));
        r.EnsureEnd();
        return m;
    }
}

public sealed record IncomingMessage(byte[] Token, string ViewerAddress)
{
    public byte[] Serialize() => new ProtoWriter().Fixed(Token).Str(ViewerAddress).ToArray();

    public static IncomingMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new IncomingMessage(r.Fixed(RelayLimits.TokenLength), r.Str(64));
        r.EnsureEnd();
        return m;
    }
}

public sealed record AcceptMessage(string AccessKey, string Id, byte[] Token)
{
    public byte[] Serialize() => new ProtoWriter().Str(AccessKey).Str(Id).Fixed(Token).ToArray();

    public static AcceptMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new AcceptMessage(r.Str(RelayLimits.MaxAccessKeyChars), r.Str(Config.ConnectionId.MaxLength), r.Fixed(RelayLimits.TokenLength));
        r.EnsureEnd();
        return m;
    }
}

public sealed record ConnectMessage(string AccessKey, string Id)
{
    public byte[] Serialize() => new ProtoWriter().Str(AccessKey).Str(Id).ToArray();

    public static ConnectMessage Parse(byte[] p)
    {
        var r = new ProtoReader(p);
        var m = new ConnectMessage(r.Str(RelayLimits.MaxAccessKeyChars), r.Str(Config.ConnectionId.MaxLength));
        r.EnsureEnd();
        return m;
    }
}
