using System.Globalization;

namespace SkillGuard.Core;

public sealed class ConsoleReporter(bool useColor = true) : IReporter
{
    public void Write(ScanReport report, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);
        foreach (var group in report.ByFile())
        {
            output.WriteLine(group.Key);
            foreach (var finding in group)
            {
                var marker = SeverityLabel(finding.Severity);
                if (useColor) marker = Colorize(finding.Severity, marker);
                output.WriteLine($"  {finding.Location.Line}:{finding.Location.Column}  {marker}  {finding.RuleId}  {finding.Message}");
                if (finding.Snippet.Length > 0) output.WriteLine($"      > {finding.Snippet}");
            }
            output.WriteLine();
        }
        output.WriteLine(string.Create(CultureInfo.InvariantCulture,
            $"{report.FilesScanned} file(s) scanned, {report.RulesExecuted} rule(s), {report.Findings.Count} finding(s) in {report.Elapsed.TotalMilliseconds:F0} ms"));
        output.WriteLine(RiskScore.From(report).Summary());
    }

    public static string SeverityLabel(Severity severity) => severity switch
    {
        Severity.Critical => "CRITICAL",
        Severity.High => "HIGH",
        Severity.Medium => "MEDIUM",
        Severity.Low => "LOW",
        _ => "NOTE"
    };

    private static string Colorize(Severity severity, string text) => severity switch
    {
        Severity.Critical or Severity.High => $"\x1b[31m{text}\x1b[0m",
        Severity.Medium => $"\x1b[33m{text}\x1b[0m",
        Severity.Low => $"\x1b[36m{text}\x1b[0m",
        _ => text
    };
}
