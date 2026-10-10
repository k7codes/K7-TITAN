using K7Titan.Core;
using K7Titan.Realtime;

namespace K7Titan.App.Services;

public sealed class AppServices
{
    public IScanService Scanner { get; }
    public IExclusionService Exclusions { get; }
    public ScanOrchestrator Orchestrator { get; }
    public IQuarantineService Quarantine { get; }
    public IReportService Reports { get; }
    public RealtimeProtectionService Realtime { get; }
    public ScanLog Log { get; } = new();

    public bool RealtimeEnabled { get; private set; }
    public string EngineVersion => "0.2.0";

    public AppServices()
    {
        Scanner = new EngineScanner();
        Exclusions = new ExclusionService();
        Orchestrator = new ScanOrchestrator(Scanner, Exclusions);
        Quarantine = new QuarantineService();
        Reports = new JsonReportService();
        Realtime = new RealtimeProtectionService(Scanner);
        Realtime.ThreatDetected += d =>
            Log.Add(new Detection(d.Path, d.ThreatName, ThreatLevel.Medium, d.Score, "realtime", d.Timestamp));
    }

    public void StartRealtime(IEnumerable<string> directories)
    {
        if (RealtimeEnabled) return;
        foreach (var dir in directories)
        {
            Realtime.Watch(dir);
        }
        RealtimeEnabled = true;
        Log.Add(new Detection(string.Empty, "Real-time protection started", ThreatLevel.Clean, 0, "system", DateTime.UtcNow));
    }

    public void StopRealtime()
    {
        Realtime.Dispose();
        RealtimeEnabled = false;
    }
}
