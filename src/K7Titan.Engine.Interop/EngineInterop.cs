using System;
using System.Runtime.InteropServices;

namespace K7Titan.Engine.Interop;

public enum ScanVerdict : int
{
    Clean = 0,
    Suspicious = 1,
    Malicious = 2,
    Unknown = 3
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct ScanResult
{
    public ScanVerdict Verdict;
    public IntPtr ThreatName;
    [MarshalAs(UnmanagedType.R4)]
    public float Score;
}

public static class NativeEngine
{
    private const string DllName = "K7TitanEngine";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern void K7tInitEngine();

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern void K7tShutdownEngine();

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int K7tScanFile(string path, out ScanResult result);
}
