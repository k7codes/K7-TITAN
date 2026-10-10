using System;
using System.IO;
using K7Titan.Core;
using Xunit;

namespace K7Titan.Core.Tests;

public class ScanEngineTests
{
    private const string EicarSignature = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    [Fact]
    public async Task DetectsEicarTestFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"k7_eicar_{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(path, EicarSignature);
            var scanner = new EngineScanner();
            var result = await scanner.ScanAsync(path, default);
            Assert.True(result.IsThreat, "EICAR should be flagged as a threat");
            Assert.Contains("EICAR", result.ThreatName, StringComparison.OrdinalIgnoreCase);
            Assert.True(result.Score >= 1.0f);
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task CleanFileIsNotFlagged()
    {
        var path = Path.Combine(Path.GetTempPath(), $"k7_clean_{Guid.NewGuid():N}.txt");
        try
        {
            await File.WriteAllTextAsync(path, "hello world, this is a perfectly clean text file.");
            var scanner = new EngineScanner();
            var result = await scanner.ScanAsync(path, default);
            Assert.False(result.IsThreat, "Clean file must not be flagged");
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }

    [Fact]
    public async Task OrchestratorFindsEicarAndSkipsCleanFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"k7_dir_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(dir, "clean.txt"), "totally clean content");
            await File.WriteAllTextAsync(Path.Combine(dir, "eicar.txt"), EicarSignature);

            var scanner = new EngineScanner();
            var exclusions = new ExclusionService(loadDefaults: false);
            var orchestrator = new ScanOrchestrator(scanner, exclusions);

            var report = await orchestrator.ScanAsync(dir, new ScanOptions(), null, default);

            Assert.Equal(2, report.Statistics.FilesScanned);
            Assert.Single(report.Detections);
            Assert.Contains("EICAR", report.Detections[0].ThreatName, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }
}
