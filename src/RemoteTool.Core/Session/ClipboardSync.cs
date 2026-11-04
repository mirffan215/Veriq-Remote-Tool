using System.Security.Cryptography;
using System.Text;
using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

/// <summary>Abstraction over the OS clipboard (WPF implementation lives in the App).</summary>
public interface IClipboardAccess : IDisposable
{
    string? GetText();
    void SetText(string text);
    /// <summary>Raised (any thread) when the local clipboard content changed.</summary>
    event Action? Changed;
}

/// <summary>
/// Two-way plain-text clipboard sync with echo suppression and a size cap. Only active when the Clipboard permission
/// was granted; only the type and size are audited, never the content.
/// </summary>
public sealed class ClipboardSync : IDisposable
{
    private readonly IClipboardAccess _clip;
    private readonly Func<byte[], Task> _send;
    private readonly IAuditLog _audit;
    private readonly object _gate = new();
    private byte[]? _lastSetHash;
    private bool _disposed;

    public ClipboardSync(IClipboardAccess clip, Func<byte[], Task> sendPayload, IAuditLog audit)
    {
        _clip = clip;
        _send = sendPayload;
        _audit = audit;
    }

    public void Start() => _clip.Changed += OnLocalChanged;

    private async void OnLocalChanged()
    {
        try
        {
            if (_disposed) return;
            var text = _clip.GetText();
            if (string.IsNullOrEmpty(text)) return;
            var bytes = Encoding.UTF8.GetByteCount(text);
            if (bytes > ProtocolConstants.MaxClipboardBytes) { _audit.Write("clipboard_blocked", ("reason", "too-large"), ("bytes", bytes)); return; }
            lock (_gate)
                if (_lastSetHash is not null && CryptographicOperations.FixedTimeEquals(_lastSetHash, Hash(text))) return; // echo of what we just received
            await _send(new ClipboardDataMessage(text).Serialize()).ConfigureAwait(false);
            _audit.Write("clipboard_sent", ("type", "text"), ("bytes", bytes));
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or OperationCanceledException or ProtocolException) { }
        catch (System.Runtime.InteropServices.ExternalException) { } // clipboard locked by another process
    }

    public void Receive(byte[] payload)
    {
        var msg = ClipboardDataMessage.Parse(payload);
        lock (_gate) _lastSetHash = Hash(msg.Text);
        try { _clip.SetText(msg.Text); }
        catch (System.Runtime.InteropServices.ExternalException) { return; }
        _audit.Write("clipboard_received", ("type", "text"), ("bytes", Encoding.UTF8.GetByteCount(msg.Text)));
    }

    private static byte[] Hash(string t) => SHA256.HashData(Encoding.UTF8.GetBytes(t));

    public void Dispose()
    {
        _disposed = true;
        _clip.Changed -= OnLocalChanged;
        _clip.Dispose();
    }
}
