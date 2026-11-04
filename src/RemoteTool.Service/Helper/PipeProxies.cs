using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;

namespace RemoteTool.Service.Helper;

/// <summary>Service-side <see cref="ISasSender"/>: sends Ctrl+Alt+Del (Secure Attention Sequence). Only a service may do this.</summary>
public interface ISasSender { void SendSas(); }

/// <summary>Frame producer that delegates capture to the session helper over the local pipe.</summary>
public sealed class PipeFrameProducer : IFrameProducer, IH264Source
{
    private readonly HelperChannel _ch;
    public PipeFrameProducer(HelperChannel channel) { _ch = channel; }

    public bool H264Available => _ch.Hello.H264;
    public IReadOnlyList<MonitorInfo> GetMonitors() => _ch.GetMonitorsAsync().GetAwaiter().GetResult();
    public FrameUpdateMessage? NextFrame(int monitorIndex, int quality, bool keyframe) => _ch.NextFrameAsync(monitorIndex, quality, keyframe).GetAwaiter().GetResult();
    public VideoFrameMessage? NextH264(int monitorIndex, bool keyframe, int bitrateKbps) => _ch.NextH264Async(monitorIndex, keyframe, bitrateKbps).GetAwaiter().GetResult();
    public CursorShape GetCursorShape()
    {
        try { return _ch.GetCursorAsync().GetAwaiter().GetResult(); }
        catch (HelperException) { return CursorShape.Arrow; } // cosmetic only
    }
    public void Dispose() { }
}

/// <summary>Injects input through the helper (which is attached to the current input desktop) and sends Ctrl+Alt+Del itself.</summary>
public sealed class PipeInputInjector : IInputInjector, ISpecialKeys
{
    private readonly HelperChannel _ch;
    private readonly ISasSender _sas;
    public PipeInputInjector(HelperChannel channel, ISasSender sas) { _ch = channel; _sas = sas; }

    public void Mouse(MonitorInfo monitor, MouseEventMessage e) { try { _ch.SendMouseAsync(monitor, e).GetAwaiter().GetResult(); } catch (IOException) { } }
    public void Key(KeyEventMessage e) { try { _ch.SendKeyAsync(e).GetAwaiter().GetResult(); } catch (IOException) { } }
    public void ReleaseAll() { try { _ch.ReleaseAllAsync().GetAwaiter().GetResult(); } catch (IOException) { } }
    public void SendCtrlAltDel() => _sas.SendSas();
    public void Dispose() { }
}
