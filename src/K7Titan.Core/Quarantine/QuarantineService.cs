using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace K7Titan.Core;

public sealed class QuarantineService : IQuarantineService
{
    private readonly string _entriesDir;
    private readonly string _indexFile;
    private readonly List<QuarantineRecord> _history = new();

    public QuarantineService(string? root = null)
    {
        root ??= Path.Combine(AppContext.BaseDirectory, "quarantine");
        _entriesDir = Path.Combine(root, "entries");
        _indexFile = Path.Combine(root, "index.json");
        Directory.CreateDirectory(_entriesDir);
        LoadIndex();
    }

    public IReadOnlyList<QuarantineRecord> History => _history;

    public async Task<QuarantineRecord?> QuarantineAsync(string originalPath, string threatName, float score, bool userConfirmed, CancellationToken ct)
    {
        if (!File.Exists(originalPath))
            return null;

        if (!userConfirmed)
        {
            var rejected = new QuarantineRecord(originalPath, string.Empty, threatName, score, DateTime.UtcNow, QuarantineDecision.Rejected);
            await AppendAsync(rejected, ct);
            return rejected;
        }

        var id = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var stored = Path.Combine(_entriesDir, id + ".k7q");
        File.Move(originalPath, stored, overwrite: true);

        var record = new QuarantineRecord(originalPath, stored, threatName, score, DateTime.UtcNow, QuarantineDecision.AllowToQuarantine);
        await AppendAsync(record, ct);
        return record;
    }

    public async Task<bool> RestoreAsync(string storedName, CancellationToken ct)
    {
        var record = _history.FirstOrDefault(r => r.StoredName == storedName);
        if (record is null || !File.Exists(record.StoredName)) return false;

        Directory.CreateDirectory(Path.GetDirectoryName(record.OriginalPath) ?? ".");
        File.Move(record.StoredName, record.OriginalPath, overwrite: true);

        var restored = record with { Decision = QuarantineDecision.Restored, Timestamp = DateTime.UtcNow };
        await AppendAsync(restored, ct);
        return true;
    }

    private void LoadIndex()
    {
        if (!File.Exists(_indexFile)) return;
        try
        {
            var json = File.ReadAllText(_indexFile);
            var list = JsonSerializer.Deserialize<List<QuarantineRecord>>(json);
            if (list is not null) _history.AddRange(list);
        }
        catch { }
    }

    private async Task AppendAsync(QuarantineRecord record, CancellationToken ct)
    {
        _history.Add(record);
        var json = JsonSerializer.Serialize(_history, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(_indexFile, json, ct);
    }
}
