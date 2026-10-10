namespace K7Titan.Core;

public sealed class ScanStatistics
{
    public int FilesScanned { get; set; }
    public int FilesSkipped { get; set; }
    public int ThreatsFound { get; set; }
    public int Errors { get; set; }
    public TimeSpan Elapsed { get; set; }

    public double FilesPerSecond =>
        Elapsed.TotalSeconds > 0 ? FilesScanned / Elapsed.TotalSeconds : 0;
}
