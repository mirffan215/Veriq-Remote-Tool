using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemoteTool.Service.Helper;

namespace RemoteTool.Service.Windows;

/// <summary>
/// Ctrl+Alt+Del via the documented SendSAS API. Services (and only services, unless a policy is set) may call it; this is why the
/// service - not the helper - performs this action. Needs validation on a real Windows 11 machine (docs/SERVICE.md, validation checklist).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSasSender : ISasSender
{
    public void SendSas() => SendSAS(false);

    [DllImport("sas.dll")] private static extern void SendSAS([MarshalAs(UnmanagedType.Bool)] bool asUser);
}
