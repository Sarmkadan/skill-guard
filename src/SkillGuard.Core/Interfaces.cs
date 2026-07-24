namespace SkillGuard.Core;

public interface IScanRule
{
    string Id { get; }
    string Name { get; }
    string Description { get; }
    Severity DefaultSeverity { get; }
    FindingCategory Category { get; }
    IEnumerable<Finding> Scan(ScanTarget target);
}

public interface IScanner
{
    ScanReport Scan(IEnumerable<ScanTarget> targets);
}

public interface IReporter
{
    void Write(ScanReport report, TextWriter output);
}

public interface IFileDiscovery
{
    IEnumerable<string> Discover(string rootPath);
}

/// <summary>
/// Optional interface for rules that can provide automatic fix suggestions.
/// Rules implementing this interface can dynamically generate fixes based on the finding details.
/// </summary>
public interface ISuggestsFix
{
    /// <summary>
    /// Provides a fix for a specific finding.
    /// </summary>
    /// <param name="finding">The finding to provide a fix for</param>
    /// <returns>A Fix object if a fix can be suggested, null otherwise</returns>
    Fix? SuggestFix(Finding finding);
}

public interface IRuleWithFixes : IScanRule, ISuggestsFix
{
    // Marker interface combining both capabilities
}
