using System.IO;
using K7Titan.Core;

namespace K7Titan.Realtime;

public record RealtimeDetection(string Path, string ThreatName, float Score, DateTime Timestamp);

public sealed class RealtimeProtectionService : IDisposable
{
    private readonly IScanService _scanner;
    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly HashSet<string> _inFlight = new(StringComparer.OrdinalIgnoreCase);

    public event Action<RealtimeDetection>? ThreatDetected;

    public RealtimeProtectionService(IScanService scanner) => _scanner = scanner;

    public void Watch(string directory, bool includeSubdirectories = true)
    {
        if (!Directory.Exists(directory)) return;
        var watcher = new FileSystemWatcher(directory)
        {
            IncludeSubdirectories = includeSubdirectories,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
            EnableRaisingEvents = true
        };
        watcher.Created += (_, e) => Queue(e.FullPath);
        watcher.Changed += (_, e) => Queue(e.FullPath);
        watcher.Renamed += (_, e) => Queue(e.FullPath);
        _watchers.Add(watcher);
    }

    private void Queue(string path) => _ = Task.Run(() => ScanAsync(path));

    private async Task ScanAsync(string path)
    {
        lock (_inFlight)
        {
            if (!_inFlight.Add(path)) return;
        }
        try
        {
            await Task.Delay(150);
            var result = await _scanner.ScanAsync(path, default);
            if (result.IsThreat)
            {
                ThreatDetected?.Invoke(new RealtimeDetection(path, result.ThreatName, result.Score, DateTime.UtcNow));
            }
        }
        catch { }
        finally
        {
            lock (_inFlight) { _inFlight.Remove(path); }
        }
    }

    public void Dispose()
    {
        foreach (var w in _watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
        _watchers.Clear();
    }
}
