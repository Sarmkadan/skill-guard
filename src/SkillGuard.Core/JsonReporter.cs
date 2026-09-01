using System.Text.Json;

namespace SkillGuard.Core;

/// <summary>
/// Generates machine-readable JSON output from scan reports.
/// </summary>
public sealed class JsonReporter : IReporter
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    /// <summary>
    /// Writes the scan report in JSON format to the specified output.
    /// </summary>
    public void Write(ScanReport report, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(report.Findings);

        var document = new
        {
            findings = report.Findings.Select(f => new
            {
                ruleId = f.RuleId,
                severity = f.Severity.ToString(),
                message = f.Message,
                file = f.Location.FilePath,
                line = f.Location.Line,
                column = f.Location.Column,
                snippet = f.Snippet
            }).ToArray(),
            fileCount = report.FilesScanned,
            ruleCount = report.RulesExecuted,
            elapsed = report.Elapsed.TotalMilliseconds
        };

        output.WriteLine(JsonSerializer.Serialize(document, Options));
    }
}
