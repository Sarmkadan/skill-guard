using System;
using SkillGuard.Core;
using SkillGuard.Rules;

namespace SkillGuard.Cli;

public class ScanRunner : IEquatable<ScanRunner>
{
    private const string FormatSarif = "sarif";
    private const string FormatConsole = "console";
    private const int ExitSuccess = 0;
    private const int ExitFailure = 1;

    public static int Run(string path, string format, string? outputPath, string failOn, string[] disabledRules, string[] allowedHosts, bool noColor, bool showFixes = false, string? diffRange = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(format);
        ArgumentException.ThrowIfNullOrWhiteSpace(failOn);

        var rules = RuleCatalog.Filter(RuleCatalog.CreateDefaultRules(allowedHosts), disabledRules);

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

        IReporter reporter = format.ToLowerInvariant() switch
        {
            FormatSarif => new SarifReporter(),
            FormatConsole => new ConsoleReporter(!noColor && outputPath is null),
            _ => throw new ArgumentException($"Unknown format '{format}'. Supported: {FormatConsole}, {FormatSarif}")
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

    // IEquatable implementation for ScanRunner
    public bool Equals(ScanRunner? other)
    {
        // ScanRunner has no instance state; all instances are considered equal
        return other is not null;
    }

    public override bool Equals(object? obj) => Equals(obj as ScanRunner);

    public override int GetHashCode()
    {
        // No instance fields to hash; return a constant
        return HashCode.Combine(0);
    }

    public static bool operator ==(ScanRunner? left, ScanRunner? right) => Equals(left, right);

    public static bool operator !=(ScanRunner? left, ScanRunner? right) => !Equals(left, right);
}
