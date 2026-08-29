using System.Diagnostics;

namespace SkillGuard.Core;

/// <summary>
/// Provides file discovery based on git diff output.
/// Scans only files that have been changed in the specified git diff range.
/// </summary>
public sealed class GitDiffFileDiscovery : IFileDiscovery
{
    private readonly string _diffRange;
    private readonly string _basePath;

    /// <summary>
    /// Gets or sets the optional sink for verbose git diff diagnostics.
    /// </summary>
    public static Action<string>? DiagnosticSink { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="GitDiffFileDiscovery"/> class.
    /// </summary>
    /// <param name="diffRange">The git diff range to scan (e.g., "origin/main...HEAD").</param>
    /// <param name="basePath">The base directory to run git commands from (defaults to current directory).</param>
    /// <exception cref="ArgumentNullException"><paramref name="diffRange"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="diffRange"/> is empty or whitespace.</exception>
    public GitDiffFileDiscovery(string diffRange, string basePath = ".")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(diffRange);
        ArgumentException.ThrowIfNullOrWhiteSpace(basePath);

        _diffRange = diffRange;
        _basePath = basePath;
    }

    /// <summary>
    /// Discovers scannable files that have been changed in the specified git diff range.
    /// </summary>
    /// <param name="rootPath">Ignored in git diff mode; always uses the diff range.</param>
    /// <returns>An enumerable of file paths that are scannable and have been changed.</returns>
    public IEnumerable<string> Discover(string rootPath)
    {
        // rootPath is ignored in git diff mode - we always use the diff range
        return DiscoverGitDiffFiles();
    }

    /// <summary>
    /// Gets the list of files changed in the git diff range.
    /// </summary>
    /// <returns>An enumerable of file paths that have been changed.</returns>
    private IEnumerable<string> DiscoverGitDiffFiles()
    {
        if (!Directory.Exists(_basePath))
        {
            yield break;
        }

        // Check if we're in a git repository
        if (!IsGitRepository(_basePath))
        {
            yield break;
        }

        // Get the list of changed files from git diff
        var changedFiles = GetChangedFilesFromGitDiff();

        // Filter to only scannable files
        var defaultDiscovery = new DefaultFileDiscovery();
        var scannableFileCount = 0;
        foreach (var file in changedFiles)
        {
            var fullPath = Path.Combine(_basePath, file);
            if (File.Exists(fullPath) && SkillFileClassifier.IsScannable(fullPath))
            {
                scannableFileCount++;
                yield return Path.GetFullPath(fullPath);
            }
        }

        DiagnosticSink?.Invoke($"skill-guard[git-diff]: scannable-files={scannableFileCount}");
    }

    /// <summary>
    /// Checks if the specified directory is a git repository.
    /// </summary>
    /// <param name="directoryPath">The directory path to check.</param>
    /// <returns>True if the directory is a git repository; otherwise, false.</returns>
    private static bool IsGitRepository(string directoryPath)
    {
        var gitDir = Path.Combine(directoryPath, ".git");
        return Directory.Exists(gitDir);
    }

    /// <summary>
    /// Executes git diff to get the list of changed files.
    /// </summary>
    /// <returns>An enumerable of file paths that have been changed in the diff range.</returns>
    private IEnumerable<string> GetChangedFilesFromGitDiff()
    {
        var processStart = new ProcessStartInfo
        {
            FileName = "git",
            Arguments = $"diff --name-only {_diffRange}",
            WorkingDirectory = _basePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        DiagnosticSink?.Invoke($"skill-guard[git-diff]: command=\"git {ToSingleLine(processStart.Arguments)}\"");

        string output;
        string error;
        int exitCode;

        try
        {
            using var process = Process.Start(processStart);
            if (process == null)
            {
                yield break;
            }

            // Read the output asynchronously
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();

            process.WaitForExit();

            output = outputTask.Result;
            error = errorTask.Result;
            exitCode = process.ExitCode;
        }
        catch (Exception ex) when (ex is FileNotFoundException or IOException)
        {
            // Git not available or other IO error
            Console.Error.WriteLine($"warning: git diff failed: {ex.Message}");
            yield break;
        }

        DiagnosticSink?.Invoke($"skill-guard[git-diff]: exit-code={exitCode}");
        if (!string.IsNullOrWhiteSpace(error))
        {
            DiagnosticSink?.Invoke($"skill-guard[git-diff]: stderr=\"{ToSingleLine(error.Trim())}\"");
        }

        if (exitCode != 0)
        {
            // Git command failed - log to stderr but don't throw
            // This allows graceful degradation in CI environments
            if (!string.IsNullOrWhiteSpace(error))
            {
                Console.Error.WriteLine($"warning: git diff failed: {error.Trim()}");
            }
            yield break;
        }

        if (string.IsNullOrWhiteSpace(output))
        {
            DiagnosticSink?.Invoke("skill-guard[git-diff]: changed-files=0");
            yield break;
        }

        // Split by newlines and filter out empty entries
        var changedFiles = output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim())
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .ToArray();

        DiagnosticSink?.Invoke($"skill-guard[git-diff]: changed-files={changedFiles.Length}");

        foreach (var file in changedFiles)
        {
            yield return file;
        }
    }

    private static string ToSingleLine(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
}
