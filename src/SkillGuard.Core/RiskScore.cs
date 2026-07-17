namespace SkillGuard.Core;

/// <summary>
/// Aggregates the individual findings of a scan into a single weighted risk score and grade,
/// so CI dashboards and humans can compare runs at a glance instead of counting findings by hand.
/// </summary>
public sealed record RiskScore(int Points, char Grade, IReadOnlyDictionary<Severity, int> Counts)
{
    public static int Weight(Severity severity) => severity switch
    {
        Severity.Critical => 40,
        Severity.High => 15,
        Severity.Medium => 5,
        Severity.Low => 1,
        _ => 0
    };

    public static RiskScore From(ScanReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        var counts = new Dictionary<Severity, int>();
        var points = 0;
        foreach (var finding in report.Findings)
        {
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
}
