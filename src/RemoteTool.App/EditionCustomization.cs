namespace RemoteTool.App;

/// <summary>
/// Extension point for customised editions. The shared code calls <see cref="OnStartup"/> once after the application object exists; with no edition code
/// the call compiles away. An edition adds its behaviour in <c>editions\&lt;Edition&gt;\Customization\*.cs</c> by implementing the partial method:
/// <code>static partial class EditionCustomization { static partial void OnStartup(App app) { ... } }</code>
/// Keep customisations additive (branding, defaults, extra windows). Do not weaken the controls in docs\SECURITY.md.
/// </summary>
internal static partial class EditionCustomization
{
    internal static void Startup(App app) => OnStartup(app);
    static partial void OnStartup(App app);
}
