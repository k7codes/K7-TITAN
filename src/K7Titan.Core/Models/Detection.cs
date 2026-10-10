namespace K7Titan.Core;

public sealed record Detection(
    string FilePath,
    string ThreatName,
    ThreatLevel Level,
    float Score,
    string Layer,
    DateTime Timestamp);
