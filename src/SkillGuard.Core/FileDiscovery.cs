namespace SkillGuard.Core;

public sealed class DefaultFileDiscovery : IFileDiscovery
{
    private static readonly string[] SkippedDirectories = [".git", "node_modules", "bin", "obj", ".vs", ".idea"];

    public IEnumerable<string> Discover(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        return DiscoverCore(rootPath);
    }

    private static IEnumerable<string> DiscoverCore(string rootPath)
    {
        if (File.Exists(rootPath))
        {
            yield return rootPath;
            yield break;
        }
        if (!Directory.Exists(rootPath)) yield break;
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.System };
        foreach (var file in Directory.EnumerateFiles(rootPath, "*", options))
        {
            var normalized = file.Replace('\\', '/');
            if (SkippedDirectories.Any(d => normalized.Contains($"/{d}/"))) continue;
            if (SkillFileClassifier.IsScannable(file)) yield return file;
        }
    }
}
