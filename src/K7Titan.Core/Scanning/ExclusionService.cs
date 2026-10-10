using System.IO;

namespace K7Titan.Core;

public interface IExclusionService
{
    IReadOnlyCollection<string> ExcludedPaths { get; }
    IReadOnlyCollection<string> ExcludedExtensions { get; }
    void AddPath(string path);
    void AddExtension(string extension);
    bool IsExcluded(string path);
}

public sealed class ExclusionService : IExclusionService
{
    private readonly List<string> _paths = new();
    private readonly List<string> _extensions = new();

    public ExclusionService(bool loadDefaults = true)
    {
        if (!loadDefaults) return;

        _paths.AddRange(new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System Volume Information"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "WinSxS"),
            @"C:\$Recycle.Bin",
            @"C:\pagefile.sys",
            @"C:\hiberfil.sys",
            @"C:\swapfile.sys"
        });

        _extensions.AddRange(new[] { ".tmp", ".log", ".etl" });
    }

    public IReadOnlyCollection<string> ExcludedPaths => _paths;
    public IReadOnlyCollection<string> ExcludedExtensions => _extensions;

    public void AddPath(string path)
    {
        if (!string.IsNullOrWhiteSpace(path))
            _paths.Add(path.TrimEnd('\\'));
    }

    public void AddExtension(string extension)
    {
        if (string.IsNullOrWhiteSpace(extension)) return;
        if (!extension.StartsWith('.')) extension = "." + extension;
        _extensions.Add(extension);
    }

    public bool IsExcluded(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;

        foreach (var ex in _paths)
        {
            if (path.StartsWith(ex, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        var ext = Path.GetExtension(path);
        return _extensions.Any(e => string.Equals(e, ext, StringComparison.OrdinalIgnoreCase));
    }
}
