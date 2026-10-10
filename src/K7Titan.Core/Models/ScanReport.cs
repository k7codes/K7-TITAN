namespace K7Titan.Core;

public sealed class ScanReport
{
    public ScanReport(string target)
    {
        Target = target;
        StartedAt = DateTime.UtcNow;
    }

    public string Target { get; }
    public DateTime StartedAt { get; init; }
    public DateTime FinishedAt { get; set; }
    public ScanStatistics Statistics { get; set; } = new();
    public List<Detection> Detections { get; } = new();

    public bool IsClean => Detections.Count == 0;
}
