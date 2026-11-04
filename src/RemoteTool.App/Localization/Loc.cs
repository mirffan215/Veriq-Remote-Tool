using System.Globalization;
using System.Resources;
using System.Windows;
using System.Windows.Markup;

namespace RemoteTool.App.Localization;

/// <summary>
/// All user-visible text comes from Resources/Strings.resx (+ Strings.ar.resx later). Switching culture also flips
/// FlowDirection for RTL languages; XAML uses {loc:T Key}, code uses Loc.T / Loc.F.
/// </summary>
public static class Loc
{
    private static readonly ResourceManager Rm = new("RemoteTool.App.Resources.Strings", typeof(Loc).Assembly);

    public static string T(string key) => Rm.GetString(key, CultureInfo.CurrentUICulture) ?? key;
    public static string F(string key, params object[] args) => string.Format(CultureInfo.CurrentUICulture, T(key), args);

    public static FlowDirection Flow => CultureInfo.CurrentUICulture.TextInfo.IsRightToLeft ? FlowDirection.RightToLeft : FlowDirection.LeftToRight;
}

[MarkupExtensionReturnType(typeof(string))]
public sealed class TExtension : MarkupExtension
{
    public TExtension(string key) { Key = key; }
    [ConstructorArgument("key")] public string Key { get; set; }
    public override object ProvideValue(IServiceProvider serviceProvider) => Loc.T(Key);
}
