namespace K7Titan.Core;

public sealed record ScanProgress(string CurrentFile, int FilesScanned, int ThreatsFound, double Percent);
