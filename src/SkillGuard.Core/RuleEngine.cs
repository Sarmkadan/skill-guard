using System;
using System.Linq;
using System.Diagnostics;

namespace SkillGuard.Core;

public sealed class RuleEngine(IReadOnlyList<IScanRule> rules) : IScanner, IRuleEngine, IEquatable<RuleEngine>
{
    public IReadOnlyList<IScanRule> Rules { get; } = rules ?? throw new ArgumentNullException(nameof(rules));

    public bool Equals(RuleEngine? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        return Rules.SequenceEqual(other.Rules);
    }

    public override bool Equals(object? obj)
    {
        if (obj is null) return false;
        if (ReferenceEquals(this, obj)) return true;
        if (obj.GetType() != GetType()) return false;
        return Equals((RuleEngine)obj);
    }

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var rule in Rules)
        {
            hash.Add(rule);
        }
        return hash.ToHashCode();
    }

    public static bool operator ==(RuleEngine? left, RuleEngine? right)
    {
        if (left is null) return right is null;
        return left.Equals(right);
    }

    public static bool operator !=(RuleEngine? left, RuleEngine? right)
    {
        return !(left == right);
    }

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