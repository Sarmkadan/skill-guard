using System;
using SkillGuard.Core;
using SkillGuard.Rules;

namespace SkillGuard.Cli;

/// <summary>
/// Runs a scan and writes the report; returns the process exit code.
/// </summary>
public static class ScanRunner
{
    private const string FormatSarif = "sarif";
    private const string FormatJson = "json";
    private const string FormatConsole = "console";
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;
    private const int ExitUsageError = 2;

    /// <summary>
    /// Discovers and scans the target path, then writes the report in the requested format.
    /// </summary>
    /// <param name="path">File or directory to scan.</param>
    /// <param name="format">Output format: <c>console</c>, <c>json</c> or <c>sarif</c>.</param>
    /// <param name="outputPath">Optional file to write the report to instead of stdout.</param>
    /// <param name="failOn">Severity threshold (<c>never</c>, <c>note</c>, <c>low</c>, <c>medium</c>, <c>high</c>, <c>critical</c>) at which the exit code becomes non-zero.</param>
    /// <param name="disabledRules">Rule IDs to skip.</param>
    /// <param name="allowedHosts">Hosts exempt from network egress findings.</param>
    /// <param name="noColor">Disables ANSI colors in console output.</param>
    /// <param name="showFixes">Includes suggested fixes in the output.</param>
    /// <param name="diffRange">Git diff range; when set, only files changed in that range are scanned.</param>
    /// <param name="credentialFilePatterns">Extra glob patterns for credential files.</param>
    /// <returns>The process exit code.</returns>
    public static int Run(string path, string format, string? outputPath, string failOn, string[] disabledRules, string[] allowedHosts, bool noColor, bool showFixes = false, string? diffRange = null, IReadOnlyList<string>? credentialFilePatterns = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(format);
        ArgumentException.ThrowIfNullOrWhiteSpace(failOn);

        var normalizedFormat = format.ToLowerInvariant();
        if (normalizedFormat is not FormatSarif and not FormatJson and not FormatConsole)
        {
            Console.Error.WriteLine($"skill-guard: unknown format '{format}'. Supported formats: {FormatConsole}, {FormatSarif}, {FormatJson}");
            return ExitUsageError;
        }

        var rules = RuleCatalog.Filter(RuleCatalog.CreateDefaultRules(allowedHosts, credentialFilePatterns), disabledRules);

        IFileDiscovery discovery;
        if (diffRange != null)
        {
            discovery = new GitDiffFileDiscovery(diffRange, path);
        }
        else
        {
            discovery = new DefaultFileDiscovery();
        }

        var files = discovery.Discover(path).ToList();

        if (files.Count == 0)
        {
            if (diffRange != null)
            {
                Console.Error.WriteLine($"skill-guard: no scannable files changed in git diff range '{diffRange}'");
            }
            else
            {
                Console.Error.WriteLine($"skill-guard: no scannable files found under '{path}'");
            }
            return ExitSuccess;
        }

        var engine = new RuleEngine(rules);
        var report = engine.Scan(files.Select(ScanTarget.FromFile));

        IReporter reporter = normalizedFormat switch
        {
            FormatSarif => new SarifReporter(),
            FormatJson => new JsonReporter(),
            _ => new ConsoleReporter(!noColor && outputPath is null)
        };

        if (outputPath is null)
        {
            reporter.Write(report, Console.Out);
        }
        else
        {
            using var writer = new StreamWriter(outputPath);
            reporter.Write(report, writer);
            Console.WriteLine($"Report written to {outputPath}");
        }

        if (showFixes && report.HasFindings) WriteFixes(report, Console.Out);

        var threshold = ParseThreshold(failOn);
        return threshold is { } value && report.CountAtOrAbove(value) > 0 ? ExitFailure : ExitSuccess;
    }

    private static void WriteFixes(ScanReport report, TextWriter output)
    {
        output.WriteLine();
        output.WriteLine("Suggested fixes:");
        foreach (var group in report.ByFile())
        {
            output.WriteLine(group.Key);
            foreach (var finding in group)
            {
                output.WriteLine($" {finding.Location.Line}:{finding.Location.Column} {finding.RuleId} {finding.Message}");
                output.WriteLine($" fix: {FixSuggester.Suggest(finding)}");
            }
            output.WriteLine();
        }
    }

    /// <summary>
    /// Maps a <c>--fail-on</c> value to the minimum severity that triggers a non-zero exit code.
    /// </summary>
    /// <param name="failOn">The threshold name; case-insensitive.</param>
    /// <returns>The threshold severity, or <c>null</c> for <c>never</c>.</returns>
    public static Severity? ParseThreshold(string failOn) => failOn.ToLowerInvariant() switch
    {
        "never" => null,
        "note" => Severity.Note,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => throw new ArgumentException($"Unknown --fail-on value '{failOn}'. Supported: note, low, medium, high, critical, never")
    };

}
