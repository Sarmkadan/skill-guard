using System.Diagnostics;

namespace SkillGuard.Core;

public sealed class RuleEngine(IReadOnlyList<IScanRule> rules) : IScanner
{
    public IReadOnlyList<IScanRule> Rules { get; } = rules ?? throw new ArgumentNullException(nameof(rules));

    public ScanReport Scan(IEnumerable<ScanTarget> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);
        var stopwatch = Stopwatch.StartNew();
        var findings = new List<Finding>();
        var fileCount = 0;
        foreach (var target in targets)
        {
            fileCount++;
            foreach (var rule in Rules)
                findings.AddRange(rule.Scan(target));
        }
        stopwatch.Stop();
        var ordered = findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Location.FilePath, StringComparer.Ordinal)
            .ThenBy(f => f.Location.Line)
            .ToList();
        return new ScanReport(ordered, fileCount, Rules.Count, stopwatch.Elapsed);
    }
}
