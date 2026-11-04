using RemoteTool.Core.Audit;
using RemoteTool.Core.Protocol;
using RemoteTool.Core.Session;
using RemoteTool.Service.Helper;

namespace RemoteTool.Service;

/// <summary>
/// Decides unattended sessions. Auto-allow only when nobody is at the machine; ask the person if one is looking at their desktop
/// (<see cref="ServiceConfig.ConsentWhenUserPresent"/>, default on). Control is the only permission an unattended session can have.
/// </summary>
public sealed class UnattendedPolicy : IUnattendedPolicy
{
    private readonly Func<ServiceConfig> _config;
    private readonly HelperSupervisor _helpers;
    private readonly IAuditLog _audit;

    public UnattendedPolicy(Func<ServiceConfig> config, HelperSupervisor helpers, IAuditLog audit)
    {
        _config = config;
        _helpers = helpers;
        _audit = audit;
    }

    public Permissions Permissions => Permissions.Control;

    /// <summary>"Winlogon" is the secure desktop (login screen, lock screen, UAC prompt): nobody is working at their desktop. Anything else is.</summary>
    public static bool IsUserPresent(string inputDesktop) => !string.Equals(inputDesktop, "Winlogon", StringComparison.OrdinalIgnoreCase);

    public async Task<ConsentDecision> DecideAsync(ConsentRequestInfo info, CancellationToken ct)
    {
        var cfg = _config();
        if (!cfg.UnattendedEnabled)
        {
            _audit.Write("unattended_denied", ("reason", "disabled"));
            return new ConsentDecision(false, Permissions.None);
        }
        HelperChannel ch;
        try { ch = await _helpers.GetChannelAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
        catch (Exception e) when (e is TimeoutException or OperationCanceledException)
        {
            _audit.Write("unattended_denied", ("reason", "no-helper"));
            return new ConsentDecision(false, Permissions.None);
        }
        try
        {
            var desktop = await ch.GetInputDesktopAsync().ConfigureAwait(false);
            if (IsUserPresent(desktop) && cfg.ConsentWhenUserPresent)
            {
                _audit.Write("unattended_asking_user", ("desktop", desktop));
                return await ch.AskConsentAsync(info, ct).ConfigureAwait(false);
            }
            _audit.Write("unattended_auto_allow", ("desktop", desktop), ("viewer", info.ViewerName));
            return new ConsentDecision(true, info.Allowed);
        }
        catch (HelperException)
        {
            _audit.Write("unattended_denied", ("reason", "helper-lost"));
            return new ConsentDecision(false, Permissions.None);
        }
    }
}
