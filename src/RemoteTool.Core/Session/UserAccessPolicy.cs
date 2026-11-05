using RemoteTool.Core.Protocol;

namespace RemoteTool.Core.Session;

/// <summary>
/// For the normal (user-mode) app: the owner set an ACCESS PASSWORD, so a viewer who knows it connects without the Accept click
/// (like AnyDesk's "unattended access"). The red banner and the Disconnect button / emergency hotkey still apply, and the viewer gets control
/// and clipboard only (never file transfer without a click).
/// </summary>
public sealed class UserAccessPolicy : IUnattendedPolicy
{
    public Permissions Permissions => Permissions.Control | Permissions.Clipboard;
    public Task<ConsentDecision> DecideAsync(ConsentRequestInfo info, CancellationToken ct) => Task.FromResult(new ConsentDecision(true, info.Allowed));
}
