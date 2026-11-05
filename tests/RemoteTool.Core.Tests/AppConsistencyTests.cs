using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace RemoteTool.Core.Tests;

/// <summary>
/// Guards for the WPF app, which cannot be compiled on non-Windows build agents: resource keys and event handlers are checked statically,
/// so a typo is caught by `dotnet test` on any OS (the real compile happens in the Windows CI job).
/// </summary>
public class AppConsistencyTests
{
    private static string Root()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null && !File.Exists(Path.Combine(d.FullName, "RemoteTool.sln"))) d = d.Parent;
        return d?.FullName ?? throw new InvalidOperationException("repository root not found");
    }

    private static Dictionary<string, string> Resx(string file)
        => XDocument.Load(file).Root!.Elements("data").ToDictionary(e => (string)e.Attribute("name")!, e => (string)e.Element("value")!);

    private static string ResDir => Path.Combine(Root(), "src", "RemoteTool.App", "Resources");

    [Fact]
    public void EveryEnglishStringHasAnArabicTranslationWithTheSamePlaceholders()
    {
        var en = Resx(Path.Combine(ResDir, "Strings.resx"));
        var ar = Resx(Path.Combine(ResDir, "Strings.ar.resx"));
        Assert.Empty(en.Keys.Except(ar.Keys));
        Assert.Empty(ar.Keys.Except(en.Keys));
        foreach (var (k, v) in en)
        {
            var a = Regex.Matches(v, @"\{\d+\}").Select(m => m.Value).OrderBy(x => x).ToArray();
            var b = Regex.Matches(ar[k], @"\{\d+\}").Select(m => m.Value).OrderBy(x => x).ToArray();
            Assert.True(a.SequenceEqual(b), $"placeholder mismatch in '{k}'");
            Assert.False(string.IsNullOrWhiteSpace(ar[k]), $"empty translation '{k}'");
        }
    }

    [Fact]
    public void EveryKeyUsedInXamlOrCodeExists()
    {
        var keys = Resx(Path.Combine(ResDir, "Strings.resx")).Keys.ToHashSet();
        var app = Path.Combine(Root(), "src", "RemoteTool.App");
        var used = new HashSet<string>();
        foreach (var f in Directory.EnumerateFiles(app, "*.xaml", SearchOption.AllDirectories).Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")))
            foreach (Match m in Regex.Matches(File.ReadAllText(f), @"\{loc:T (\w+)\}")) used.Add(m.Groups[1].Value);
        foreach (var f in Directory.EnumerateFiles(app, "*.cs", SearchOption.AllDirectories).Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")))
            foreach (Match m in Regex.Matches(File.ReadAllText(f), @"Loc\.[TF]\(""(\w+)""")) used.Add(m.Groups[1].Value);
        // keys passed through Loc.T(cond ? "A" : "B") style expressions
        foreach (var f in Directory.EnumerateFiles(app, "*.cs", SearchOption.AllDirectories).Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")))
            foreach (Match m in Regex.Matches(File.ReadAllText(f), @"""((?:File|Svc|Viewer|Relay|Err|Banner|Rec|Lang)_\w+)""")) used.Add(m.Groups[1].Value);
        Assert.Empty(used.Except(keys));
        Assert.True(used.Count > 40);
    }

    [Fact]
    public void XamlIsWellFormedAndEveryEventHandlerExistsInCodeBehind()
    {
        var win = Path.Combine(Root(), "src", "RemoteTool.App", "Windows");
        foreach (var xaml in Directory.GetFiles(win, "*.xaml"))
        {
            var text = File.ReadAllText(xaml);
            XDocument.Parse(text);   // throws if malformed
            var code = File.ReadAllText(xaml + ".cs");
            foreach (Match m in Regex.Matches(text, @"\b(?:Click|MouseDoubleClick|MouseMove|MouseDown|MouseUp|MouseWheel|SizeChanged|Loaded)=""(\w+)"""))
                Assert.True(Regex.IsMatch(code, $@"\b{m.Groups[1].Value}\s*\("), $"{Path.GetFileName(xaml)}: handler '{m.Groups[1].Value}' not found");
            // every UI element touched from code must be declared in XAML: catches typos in control names
            var names = Regex.Matches(text, @"x:Name=""(\w+)""").Select(m => m.Groups[1].Value).ToHashSet();
            var props = "Visibility|Text|Content|IsEnabled|IsChecked|Password|ItemsSource|SelectedItem|Fill|Source|Cursor|Foreground|Header|IsOpen|Width|Height";
            foreach (Match m in Regex.Matches(code, $@"(?<![\w.])([A-Z]\w*)\.({props})\b"))
            {
                var id = m.Groups[1].Value;
                if (names.Contains(id)) continue;
                // members of the window itself (Title, Width, ...) and static types are fine; anything else is a control that does not exist
                if (id is "Visibility" or "Application" or "Cursors" or "Brushes" or "Loc" or "ConnectMode") continue;
                Assert.Fail($"{Path.GetFileName(xaml)}: code uses control '{id}.{m.Groups[2].Value}' but XAML declares no x:Name=\"{id}\"");
            }
        }
    }
}
