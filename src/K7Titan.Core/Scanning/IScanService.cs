namespace K7Titan.Core;

public interface IScanService
{
    Task<EngineScanResult> ScanAsync(string path, CancellationToken ct);
}
