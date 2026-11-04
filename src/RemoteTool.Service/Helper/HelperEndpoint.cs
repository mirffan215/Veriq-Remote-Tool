using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Service.Helper;

/// <summary>What the helper needs from its host process for the interactive bits (WPF banner, consent dialog, desktop name).</summary>
public interface IHelperUi
{
    string CurrentInputDesktop();
    void ShowBanner(string viewer, bool recording);
    void HideBanner();
    Task<ConsentDecision> AskConsentAsync(ConsentRequestInfo info);
}

/// <summary>
/// Helper-side loop: executes the service's requests with the real capture/input implementations. <see cref="Run"/> blocks the calling
/// thread - call it from a dedicated thread, because desktop attachment (SetThreadDesktop) is per thread.
/// </summary>
public sealed class HelperEndpoint
{
    private readonly Stream _stream;
    private readonly IFrameProducer _producer;
    private readonly IInputInjector _injector;
    private readonly IHelperUi _ui;
    private readonly FrameReader _reader;
    private readonly FrameWriter _writer;
    private readonly int _session;
    private readonly string _user;

    public HelperEndpoint(Stream stream, IFrameProducer producer, IInputInjector injector, IHelperUi ui, int sessionId, string userName)
    {
        _stream = stream;
        _producer = producer;
        _injector = injector;
        _ui = ui;
        _session = sessionId;
        _user = userName;
        _reader = new FrameReader(stream, HelperTypes.IsKnown, HelperTypes.MaxPayload);
        _writer = new FrameWriter(stream);
    }

    /// <summary>Raise from the UI thread when the user pressed the emergency hotkey / the banner's Disconnect button.</summary>
    public void NotifyEmergencyHotkey() => FireAndForget(HelperMessage.EmergencyHotkey);
    public void NotifyBannerDisconnect() => FireAndForget(HelperMessage.BannerDisconnect);

    private void FireAndForget(HelperMessage m)
    {
        try { _writer.WriteAsync((byte)m, Array.Empty<byte>(), CancellationToken.None).GetAwaiter().GetResult(); } catch (IOException) { } catch (ObjectDisposedException) { }
    }

    public void Run(CancellationToken ct)
    {
        _writer.WriteAsync((byte)HelperMessage.Hello, new HelperHello(Environment.ProcessId, _session, _producer is IH264Source { H264Available: true }, _user).Serialize(), ct).GetAwaiter().GetResult();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var f = _reader.ReadAsync(ct).AsTask().GetAwaiter().GetResult();
                if (!Handle(f)) break;
            }
        }
        catch (Exception e) when (e is IOException or ProtocolException or OperationCanceledException or ObjectDisposedException) { }
        finally
        {
            try { _injector.ReleaseAll(); } catch { }
            try { _ui.HideBanner(); } catch { }
        }
    }

    private bool Handle(Frame f)
    {
        try
        {
            switch ((HelperMessage)f.Type)
            {
                case HelperMessage.GetMonitors:
                    var mons = _producer.GetMonitors();
                    Reply(HelperMessage.Monitors, new ScreenInfoMessage(mons, 0).Serialize());
                    break;
                case HelperMessage.NextFrame:
                    var (mon, q, key) = HelperCodec.ParseNextFrame(f.Payload);
                    Reply(HelperMessage.Frame, HelperCodec.Optional(_producer.NextFrame(mon, q, key)?.Serialize()));
                    break;
                case HelperMessage.NextH264:
                    var (m2, k2, kbps) = HelperCodec.ParseNextH264(f.Payload);
                    if (_producer is not IH264Source h) { Reply(HelperMessage.Error, HelperCodec.Error(1, "H.264 not available in helper")); break; }
                    Reply(HelperMessage.Video, HelperCodec.Optional(h.NextH264(m2, k2, kbps)?.Serialize()));
                    break;
                case HelperMessage.GetCursor:
                    Reply(HelperMessage.Cursor, new CursorUpdateMessage(_producer.GetCursorShape()).Serialize());
                    break;
                case HelperMessage.GetDesktop:
                    Reply(HelperMessage.Desktop, new ProtoWriter().Str(_ui.CurrentInputDesktop()).ToArray());
                    break;
                case HelperMessage.Mouse:
                    var (mi, ev) = HelperCodec.ParseMouse(f.Payload);
                    _injector.Mouse(mi, ev);
                    break;
                case HelperMessage.Key:
                    _injector.Key(KeyEventMessage.Parse(f.Payload));
                    break;
                case HelperMessage.ReleaseAll:
                    _injector.ReleaseAll();
                    break;
                case HelperMessage.ShowBanner:
                    var (viewer, rec) = HelperCodec.ParseBanner(f.Payload);
                    _ui.ShowBanner(viewer, rec);
                    break;
                case HelperMessage.HideBanner:
                    _ui.HideBanner();
                    break;
                case HelperMessage.AskConsent:
                    var ci = HelperCodec.ParseConsent(f.Payload);
                    // The dialog can take a minute: answer asynchronously so the loop keeps serving requests.
                    _ = Task.Run(async () =>
                    {
                        ConsentDecision d;
                        try { d = await _ui.AskConsentAsync(new ConsentRequestInfo(ci.ViewerName, ci.Source, ci.ViaRelay, ci.Requested, ci.Allowed, ci.Recording)).ConfigureAwait(false); }
                        catch (Exception) { d = new ConsentDecision(false, Permissions.None); }
                        Reply(HelperMessage.ConsentAnswer, HelperCodec.ConsentAnswer(d.Granted, d.Permissions));
                    });
                    break;
                case HelperMessage.Shutdown:
                    return false;
                default:
                    throw new ProtocolException("unexpected request");
            }
        }
        catch (CodecUnavailableException e) { Reply(HelperMessage.Error, HelperCodec.Error(1, e.Message)); }
        catch (Exception e) when (e is not ProtocolException and not IOException and not OperationCanceledException and not ObjectDisposedException)
        {
            Reply(HelperMessage.Error, HelperCodec.Error(0, e.GetType().Name + ": " + e.Message)); // never crash the helper on a capture hiccup
        }
        return true;
    }

    private void Reply(HelperMessage m, byte[] payload)
    {
        try { _writer.WriteAsync((byte)m, payload, CancellationToken.None).GetAwaiter().GetResult(); } catch (IOException) { } catch (ObjectDisposedException) { }
    }
}
