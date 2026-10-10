using System.Diagnostics;
using System.IO;
using K7Titan.Engine.Interop;

namespace K7Titan.Core;

public sealed class ScanOrchestrator
{
    private readonly IScanService _scanner;
    private readonly IExclusionService _exclusions;

    public ScanOrchestrator(IScanService scanner, IExclusionService exclusions)
    {
        _scanner = scanner;
        _exclusions = exclusions;
    }

    public async Task<ScanReport> ScanAsync(
        string target,
        ScanOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken ct)
    {
        var report = new ScanReport(target);
        var stopwatch = Stopwatch.StartNew();

        int scanned = 0, threats = 0, skipped = 0, errors = 0;
        long maxBytes = (long)options.MaxFileSizeMb * 1024 * 1024;

        void OnError(string path, Exception ex)
        {
            _ = path;
            _ = ex;
            Interlocked.Increment(ref errors);
        }

        foreach (var file in FileWalker.Enumerate(target, options.Recurse, OnError))
        {
            ct.ThrowIfCancellationRequested();

            if (_exclusions.IsExcluded(file))
            {
                skipped++;
                continue;
            }

            try
            {
                var info = new FileInfo(file);
                if (info.Length > maxBytes)
                {
                    skipped++;
                    continue;
                }

                var result = await _scanner.ScanAsync(file, ct);
                scanned++;

                if (result.IsThreat)
                {
                    report.Detections.Add(new Detection(
                        file,
                        result.ThreatName,
                        result.Level,
                        result.Score,
                        LayerFor(result),
                        DateTime.UtcNow));
                    threats++;
                }

                progress?.Report(new ScanProgress(file, scanned, threats, 0));
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                errors++;
            }
        }

        stopwatch.Stop();
        report.Statistics = new ScanStatistics
        {
            FilesScanned = scanned,
            FilesSkipped = skipped,
            ThreatsFound = threats,
            Errors = errors,
            Elapsed = stopwatch.Elapsed
        };
        report.FinishedAt = DateTime.UtcNow;
        return report;
    }

    private static string LayerFor(EngineScanResult result) => result.Verdict switch
    {
        ScanVerdict.Suspicious => "heuristic",
        ScanVerdict.Malicious when result.ThreatName.Contains("Sig", StringComparison.OrdinalIgnoreCase) => "signature",
        ScanVerdict.Malicious => "signature",
        _ => "none"
    };
}
