using K7Titan.Engine.Interop;

namespace K7Titan.Core;

public sealed record EngineScanResult(int Status, ScanVerdict Verdict, string ThreatName, float Score)
{
    public bool IsThreat =>
        Status == 0 && (Verdict == ScanVerdict.Suspicious || Verdict == ScanVerdict.Malicious);

    public ThreatLevel Level => Verdict switch
    {
        ScanVerdict.Malicious => Score >= 1.0f ? ThreatLevel.Critical : ThreatLevel.High,
        ScanVerdict.Suspicious => ThreatLevel.Medium,
        ScanVerdict.Clean => ThreatLevel.Clean,
        _ => ThreatLevel.Low
    };
}
