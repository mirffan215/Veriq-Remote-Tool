namespace RemoteTool.Core.Protocol;

/// <summary>Raised for any malformed, oversized, unexpected or out-of-policy wire data.</summary>
public class ProtocolException : Exception
{
    public ProtocolException(string message) : base(message) { }
    public ProtocolException(string message, Exception inner) : base(message, inner) { }
}
