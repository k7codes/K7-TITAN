using System.IO;

namespace K7Titan.Core;

public static class FileWalker
{
    public static IEnumerable<string> Enumerate(string root, bool recurse, Action<string, Exception>? onError = null)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var dir = stack.Pop();

            string[] files;
            try
            {
                files = Directory.GetFiles(dir);
            }
            catch (Exception ex)
            {
                onError?.Invoke(dir, ex);
                files = Array.Empty<string>();
            }

            foreach (var file in files)
            {
                yield return file;
            }

            if (!recurse) continue;

            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(dir);
            }
            catch (Exception ex)
            {
                onError?.Invoke(dir, ex);
                continue;
            }

            foreach (var sub in subdirs)
            {
                try
                {
                    var attrs = File.GetAttributes(sub);
                    if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch (Exception ex)
                {
                    onError?.Invoke(sub, ex);
                    continue;
                }
                stack.Push(sub);
            }
        }
    }
}
