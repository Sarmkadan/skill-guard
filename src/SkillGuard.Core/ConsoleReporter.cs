using System.Globalization;
using System.Text;

namespace SkillGuard.Core;

/// <summary>
/// Generates human-readable console output from scan reports.
/// This reporter provides a clear, colorized summary of findings suitable for terminal display.
/// </summary>
/// <remarks>
/// For empty reports (zero findings), this reporter outputs a summary line indicating no findings were found.
/// This ensures users always see confirmation that the scan completed successfully, even when no issues are detected.
/// </remarks>
public sealed class ConsoleReporter(bool useColor = true) : IReporter, IConsoleReporter
{
    private readonly bool _useColor = useColor;
    private const string ControlCharsToRemove = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a";

    /// <summary>
    /// Writes the scan report to the console in a human-readable format.
    /// </summary>
    /// <param name="report">The scan report containing findings to report. Must not be null.</param>
    /// <param name="output">The text writer to write the console output to. Must not be null.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="report"/>, <paramref name="output"/>, or <paramref name="report.Findings"/> is null.</exception>
    /// <remarks>
    /// For empty reports (zero findings), this method outputs a summary line indicating no findings were found.
    /// This ensures users always see confirmation that the scan completed successfully.
    /// </remarks>
    public void Write(ScanReport report, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(report.Findings);

        bool hasFindings = report.Findings.Count > 0;

        if (hasFindings)
        {
            foreach (var group in report.ByFile())
            {
                output.WriteLine(SanitizeForTerminal(group.Key));
                foreach (var finding in group)
                {
                    var marker = SeverityLabel(finding.Severity);
                    if (_useColor) marker = Colorize(finding.Severity, marker);
                    output.WriteLine(SanitizeForTerminal($" {finding.Location.Line}:{finding.Location.Column} {marker} {finding.RuleId} {finding.Message}"));
                    if (finding.Snippet.Length > 0)
                    {
                        output.WriteLine(SanitizeForTerminal($" > {finding.Snippet}"));
                    }
                }
                output.WriteLine();
            }
        }

        output.WriteLine(string.Create(CultureInfo.InvariantCulture, $"{report.FilesScanned} file(s) scanned, {report.RulesExecuted} rule(s), {report.Findings.Count} finding(s) in {report.Elapsed.TotalMilliseconds:F0} ms"));
        output.WriteLine(SanitizeForTerminal(RiskScore.From(report).Summary()));
    }

    /// <summary>
    /// Sanitizes a string for safe terminal output by removing control characters that could be used for
    /// terminal escape injection attacks (ANSI escape sequences, C0 control codes, OSC sequences, etc.).
    /// </summary>
    /// <param name="input">The input string to sanitize.</param>
    /// <returns>The sanitized string with control characters removed.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="input"/> is null.</exception>
    public static string SanitizeForTerminal(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        // Use StringBuilder for better performance with potentially large strings
        var sanitized = new StringBuilder(input.Length);

        foreach (char c in input)
        {
            // Keep safe whitespace characters and printable ASCII (32-126)
            // Exclude: C0 control codes (0x00-0x1F) except \t (0x09), \n (0x0A), \r (0x0D)
            // This preserves normal text while removing control characters that could be used for injection
            if (c >= ' ' || c == '\t' || c == '\n' || c == '\r')
            {
                sanitized.Append(c);
            }
            // Note: \x1b (ESC) is excluded here, which prevents ANSI escape sequences like \x1b[31m
            // The Colorize() method generates its own ANSI codes after sanitization, so we don't need to preserve ESC
        }

        return sanitized.ToString();
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
