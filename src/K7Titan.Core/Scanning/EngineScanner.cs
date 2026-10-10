using System.Runtime.InteropServices;
using K7Titan.Engine.Interop;

namespace K7Titan.Core;

public sealed class EngineScanner : IScanService
{
    private static readonly object InitLock = new();
    private static bool _initialized;

    public EngineScanner()
    {
        EnsureInitialized();
    }

    private static void EnsureInitialized()
    {
        if (_initialized) return;
        lock (InitLock)
        {
            if (_initialized) return;
            NativeEngine.K7tInitEngine();
            _initialized = true;
        }
    }

    public Task<EngineScanResult> ScanAsync(string path, CancellationToken ct)
    {
        return Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            var status = NativeEngine.K7tScanFile(path, out var raw);
            var name = raw.ThreatName == IntPtr.Zero
                ? "None"
                : Marshal.PtrToStringAnsi(raw.ThreatName) ?? "None";
            return new EngineScanResult(status, raw.Verdict, name, raw.Score);
        }, ct);
    }
}
