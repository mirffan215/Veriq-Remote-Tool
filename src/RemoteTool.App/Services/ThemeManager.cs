using System.Windows;
using Microsoft.Win32;

namespace RemoteTool.App.Services;

public static class ThemeManager
{
    public static void Apply(string setting)
    {
        var dark = setting == "Dark" || (setting != "Light" && SystemPrefersDark());
        var dict = new ResourceDictionary { Source = new Uri($"Themes/{(dark ? "Dark" : "Light")}.xaml", UriKind.Relative) };
        var merged = Application.Current.Resources.MergedDictionaries;
        if (merged.Count > 0) merged[0] = dict; else merged.Add(dict);
    }

    private static bool SystemPrefersDark()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return k?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch { return false; }
    }
}
