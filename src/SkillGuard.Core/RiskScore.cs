using System;
using System.Collections.Generic;
using System.Linq;

namespace SkillGuard.Core;

/// <summary>
/// Aggregates the individual findings of a scan into a single weighted risk score and grade,
/// so CI dashboards and humans can compare runs at a glance instead of counting findings by hand.
/// </summary>
/// <remarks>
/// Severity Contract:
/// - Finding.Severity is resolved exactly once at Finding-construction time
/// - PatternDefinition.SeverityOverride takes precedence over rule's DefaultSeverity when present
/// - If PatternDefinition.SeverityOverride is null, rule's DefaultSeverity is used
/// - RiskScore.Counts uses the same Finding.Severity value that was set during Finding construction
/// - This ensures consistency: the Finding displayed to users and the RiskScore tally use identical severity values
/// </remarks>
public sealed class RiskScore : IEquatable<RiskScore>
{
    public int Points { get; init; }
    public char Grade { get; init; }
    public IReadOnlyDictionary<Severity, int> Counts { get; init; }

    public RiskScore(int points, char grade, IReadOnlyDictionary<Severity, int> counts)
    {
        Points = points;
        Grade = grade;
        Counts = counts;
    }

    /// <summary>
    /// Gets the weight multiplier for a severity level used in risk score calculation.
    /// </summary>
    /// <param name="severity">The severity level</param>
    /// <returns>The weight multiplier for the severity</returns>
    /// <exception cref="ArgumentNullException">Thrown if severity is null</exception>
    public static int Weight(Severity severity)
    {
        ArgumentNullException.ThrowIfNull(severity);
        return severity switch
        {
            Severity.Critical => 40,
            Severity.High => 15,
            Severity.Medium => 5,
            Severity.Low => 1,
            _ => 0 // Severity.Note
        };
    }

    /// <summary>
    /// Creates a RiskScore from a ScanReport by aggregating findings.
    /// </summary>
    /// <param name="report">The scan report containing findings to aggregate</param>
    /// <returns>A RiskScore with points, grade, and severity counts</returns>
    /// <exception cref="ArgumentNullException">Thrown if report is null</exception>
    /// <remarks>
    /// This method relies on Finding.Severity being already resolved at construction time.
    /// The severity values used for aggregation are identical to those displayed in the Finding objects.
    /// </remarks>
    public static RiskScore From(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var counts = new Dictionary<Severity, int>();
        var points = 0;
        foreach (var finding in report.Findings)
        {
            // Use the already-resolved Finding.Severity - this is the same value
            // that was set during Finding construction and displayed to users
            counts[finding.Severity] = counts.GetValueOrDefault(finding.Severity) + 1;
            points += Weight(finding.Severity);
        }
        return new RiskScore(points, GradeFor(points), counts);
    }

    // A/B/C/D/F on the same intuition as a report card: any Critical alone (40) lands in D or worse.
    private static char GradeFor(int points) => points switch
    {
        0 => 'A',
        <= 4 => 'B',
        <= 14 => 'C',
        <= 39 => 'D',
        _ => 'F'
    };

    public string Summary()
    {
        var parts = new List<string>();
        foreach (var severity in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            if (Counts.GetValueOrDefault(severity) is var n && n > 0)
                parts.Add($"{n} {ConsoleReporterLabel(severity)}");
        var breakdown = parts.Count == 0 ? "no findings" : string.Join(", ", parts);
        return $"risk {Points} (grade {Grade}) - {breakdown}";
    }

    private static string ConsoleReporterLabel(Severity severity) => severity switch
    {
        Severity.Critical => "critical",
        Severity.High => "high",
        Severity.Medium => "medium",
        Severity.Low => "low",
        _ => "note"
    };

    // IEquatable<RiskScore> implementation
    public bool Equals(RiskScore? other)
    {
        if (ReferenceEquals(null, other)) return false;
        if (ReferenceEquals(this, other)) return true;
        return Points == other.Points &&
               Grade == other.Grade &&
               EqualityComparer<IReadOnlyDictionary<Severity, int>>.Default.Equals(Counts, other.Counts);
    }

    public override bool Equals(object? obj) => Equals(obj as RiskScore);

    public override int GetHashCode() => HashCode.Combine(Points, Grade, Counts);

    public static bool operator ==(RiskScore? left, RiskScore? right) => Equals(left, right);

    public static bool operator !=(RiskScore? left, RiskScore? right) => !Equals(left, right);
}
