using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace K7Titan.Core;

public sealed class JsonReportService : IReportService
{
    public async Task<string> WriteJsonAsync(ScanReport report, string outputDirectory, CancellationToken ct)
    {
        Directory.CreateDirectory(outputDirectory);
        var path = Path.Combine(outputDirectory, $"k7titan-report-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");

        var dto = new
        {
            target = report.Target,
            startedAt = report.StartedAt,
            finishedAt = report.FinishedAt,
            statistics = report.Statistics,
            detections = report.Detections
        };

        var json = JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(path, json, ct);
        return path;
    }

    public async Task<string> WriteCsvAsync(ScanReport report, string outputDirectory, CancellationToken ct)
    {
        Directory.CreateDirectory(outputDirectory);
        var path = Path.Combine(outputDirectory, $"k7titan-report-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv");

        var sb = new StringBuilder();
        sb.AppendLine("FilePath,ThreatName,Level,Score,Layer,Timestamp");
        foreach (var d in report.Detections)
        {
            sb.Append(Escape(d.FilePath)).Append(',')
              .Append(Escape(d.ThreatName)).Append(',')
              .Append(d.Level).Append(',')
              .Append(d.Score.ToString(CultureInfo.InvariantCulture)).Append(',')
              .Append(d.Layer).Append(',')
              .Append(d.Timestamp.ToString("o", CultureInfo.InvariantCulture))
              .AppendLine();
        }

        await File.WriteAllTextAsync(path, sb.ToString(), ct);
        return path;
    }

    private static string Escape(string value) =>
        value.Contains(',') || value.Contains('"')
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;
}
