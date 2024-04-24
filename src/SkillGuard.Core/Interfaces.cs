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
