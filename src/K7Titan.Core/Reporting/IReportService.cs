namespace K7Titan.Core;

public interface IReportService
{
    Task<string> WriteJsonAsync(ScanReport report, string outputDirectory, CancellationToken ct);
    Task<string> WriteCsvAsync(ScanReport report, string outputDirectory, CancellationToken ct);
}
