using System;
using System.IO;
using System.Linq;
using K7Titan.Core;
using Xunit;

namespace K7Titan.Core.Tests;

public class ExclusionAndWalkerTests
{
    [Fact]
    public void ExcludesByExtension()
    {
        var exclusions = new ExclusionService(loadDefaults: false);
        exclusions.AddExtension(".tmp");
        Assert.True(exclusions.IsExcluded(@"C:\anything\file.tmp"));
        Assert.False(exclusions.IsExcluded(@"C:\anything\file.txt"));
    }

    [Fact]
    public void ExcludesByPath()
    {
        var exclusions = new ExclusionService(loadDefaults: false);
        exclusions.AddPath(@"C:\Windows");
        Assert.True(exclusions.IsExcluded(@"C:\Windows\System32\kernel32.dll"));
        Assert.False(exclusions.IsExcluded(@"C:\Users\file.txt"));
    }

    [Fact]
    public void FileWalkerEnumeratesFilesWithoutThrowingOnErrors()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"k7_walk_{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "a.txt"), "a");
            File.WriteAllText(Path.Combine(dir, "b.txt"), "b");

            var files = FileWalker.Enumerate(dir, true).ToList();

            Assert.Equal(2, files.Count);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task MissingFileReturnsNonThreat()
    {
        var scanner = new EngineScanner();
        var result = await scanner.ScanAsync(@"C:\does\not\exist\nope.bin", default);
        Assert.False(result.IsThreat);
    }
}
