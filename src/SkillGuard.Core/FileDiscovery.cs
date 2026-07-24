namespace SkillGuard.Core;

/// <summary>
/// Discovers scannable files under a given root path.
/// Implements security hardening against path traversal and symlink escape attacks.
/// </summary>
public sealed class DefaultFileDiscovery : IFileDiscovery
{
	private static readonly string[] SkippedDirectories =[".git", "node_modules", "bin", "obj", ".vs", ".idea"];

	/// <summary>
	/// Gets or sets whether to follow symbolic links during directory traversal.
	/// When false (default), symbolic links are not followed and are silently skipped.
	/// When true, symbolic links are followed but their targets are validated against the root boundary.
	/// </summary>
	public bool FollowSymlinks { get; set; } = false;

	/// <summary>
	/// Discovers scannable files under the specified root path.
	/// </summary>
	/// <param name="rootPath">The root directory to scan. Must be an absolute path.</param>
	/// <returns>An enumerable of scannable file paths relative to the root.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="rootPath"/> is null.</exception>
	/// <exception cref="ArgumentException"><paramref name="rootPath"/> is empty or consists only of whitespace.</exception>
	public IEnumerable<string> Discover(string rootPath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
		return DiscoverCore(rootPath);
	}

	private IEnumerable<string> DiscoverCore(string rootPath)
	{
		if (File.Exists(rootPath))
		{
			// Even for a single file, validate it's within the intended root
			if (TryGetCanonicalRoot(rootPath, out var canonicalRoot) &&
				IsPathWithinRoot(rootPath, canonicalRoot))
			{
				yield return rootPath;
			}
			yield break;
		}

		if (!Directory.Exists(rootPath))
		{
			yield break;
		}

		var canonicalRootPath = TryGetCanonicalRoot(rootPath, out var root)
			? root
			: Path.GetFullPath(rootPath);

		var options = new EnumerationOptions
		{
			RecurseSubdirectories = true,
			IgnoreInaccessible = true,
			AttributesToSkip = FileAttributes.System
		};

		if (!FollowSymlinks)
		{
			// When not following symlinks, explicitly skip them
			options.AttributesToSkip |= FileAttributes.ReparsePoint;
		}

		foreach (var file in Directory.EnumerateFiles(rootPath, "*", options))
		{
			if (!TryGetCanonicalRoot(file, out var canonicalFilePath))
			{
				// Failed to get canonical path, skip this file
				continue;
			}

			// Security validation: ensure resolved path stays within root boundary
			if (!IsPathWithinRoot(canonicalFilePath, canonicalRootPath))
			{
				// Skip files that escape the root directory
				continue;
			}

			var normalized = file.Replace('\\', '/');
			if (SkippedDirectories.Any(d => normalized.Contains($"/{d}/"))) continue;
			if (SkillFileClassifier.IsScannable(file)) yield return file;
		}
	}

	/// <summary>
	/// Attempts to get the canonical (absolute, normalized) path for a file or directory.
	/// </summary>
	/// <param name="path">The path to canonicalize.</param>
	/// <param name="canonicalPath">Output parameter receiving the canonical path if successful.</param>
	/// <returns>True if canonicalization succeeded; false otherwise.</returns>
	private static bool TryGetCanonicalRoot(string path, out string canonicalPath)
	{
		canonicalPath = null!;
		try
		{
			// Get absolute path and normalize it
			var fullPath = Path.GetFullPath(path);

			// Normalize path separators and remove any trailing separators
			fullPath = fullPath.Replace('\\', '/').TrimEnd('/');

			// Resolve any relative segments and get the final absolute path
			// Path.GetFullPath already handles ".." segments, but we verify by checking existence
			if (File.Exists(fullPath) || Directory.Exists(fullPath))
			{
				canonicalPath = fullPath;
				return true;
			}
		}
		catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
		{
			// Invalid path format, too long, or other issues
			return false;
		}

		return false;
	}

	/// <summary>
	/// Determines whether a file path is within a root directory boundary.
	/// </summary>
	/// <param name="filePath">The absolute file path to check.</param>
	/// <param name="rootPath">The absolute root directory path.</param>
	/// <returns>True if the file path is within the root directory; false otherwise.</returns>
	private static bool IsPathWithinRoot(string filePath, string rootPath)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
		ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);

		// Normalize paths with forward slashes for comparison
		var normalizedFile = filePath.Replace('\\', '/');
		var normalizedRoot = rootPath.Replace('\\', '/').TrimEnd('/');

		// If the file path starts with the root path, it's within bounds
		// Ensure proper path boundary by checking for path separator after root
		if (normalizedFile.StartsWith(normalizedRoot, StringComparison.Ordinal))
		{
			// Check if the match ends at a path boundary (either end of string or followed by separator)
			var boundaryIndex = normalizedRoot.Length;
			if (boundaryIndex >= normalizedFile.Length)
			{
				return true; // Exact match
			}

			var nextChar = normalizedFile[boundaryIndex];
			return nextChar == '/' || nextChar == '\\';
		}

	return false;
	}
}
