using RemoteTool.Core.Config;

namespace RemoteTool.App.Services;

/// <summary>Reads the edition (name, data folder, banner) that the build embedded. No embedded edition = the plain default.</summary>
public static class EditionLoader
{
    public static EditionInfo Load()
    {
        using var s = typeof(EditionLoader).Assembly.GetManifestResourceStream("RemoteTool.edition.json");
        if (s is null) return EditionInfo.Standard;
        using var r = new StreamReader(s);
        return EditionInfo.Parse(r.ReadToEnd());
    }
}
