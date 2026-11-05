namespace RemoteTool.App;

// Code that belongs ONLY to the Enterprise edition lives in this folder (editions\Enterprise\Customization\).
// It is compiled into the app only when building with -p:Edition=Enterprise. Production and UAT never see it.
internal static partial class EditionCustomization
{
    static partial void OnStartup(App app)
    {
        // Example hooks (add your own): company branding, extra start-up checks, enterprise-only windows.
        // Keep it additive: do not bypass Accept/consent, the audit log, or any control from docs\SECURITY.md.
    }
}
