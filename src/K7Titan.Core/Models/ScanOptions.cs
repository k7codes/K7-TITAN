namespace K7Titan.Core;

public sealed class ScanOptions
{
    public bool Recurse { get; set; } = true;
    public int MaxFileSizeMb { get; set; } = 64;
    public bool ScanInsideArchives { get; set; } = false;
    public bool LowConfidenceAsThreat { get; set; } = false;
    public IReadOnlyCollection<string> ExcludedPaths { get; set; } = Array.Empty<string>();
    public IReadOnlyCollection<string> ExcludedExtensions { get; set; } = Array.Empty<string>();
}
