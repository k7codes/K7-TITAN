namespace K7Titan.Core;

public enum QuarantineDecision
{
    AllowToQuarantine,
    Restored,
    Rejected
}

public sealed record QuarantineRecord(
    string OriginalPath,
    string StoredName,
    string ThreatName,
    float Score,
    DateTime Timestamp,
    QuarantineDecision Decision);

public interface IQuarantineService
{
    IReadOnlyList<QuarantineRecord> History { get; }
    Task<QuarantineRecord?> QuarantineAsync(string originalPath, string threatName, float score, bool userConfirmed, CancellationToken ct);
    Task<bool> RestoreAsync(string storedName, CancellationToken ct);
}
