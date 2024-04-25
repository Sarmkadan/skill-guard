using SkillGuard.Core;
using SkillGuard.Rules;

namespace SkillGuard.Cli;

public static class ScanRunner
{
    public static int Run(string path, string format, string? outputPath, string failOn, string[] disabledRules, string[] allowedHosts, bool noColor)
    {
        var rules = RuleCatalog.Filter(RuleCatalog.CreateDefaultRules(allowedHosts), disabledRules);
        var discovery = new DefaultFileDiscovery();
        var files = discovery.Discover(path).ToList();
        if (files.Count == 0)
        {
            Console.Error.WriteLine($"skill-guard: no scannable files found under '{path}'");
            return 0;
        }
        var engine = new RuleEngine(rules);
        var report = engine.Scan(files.Select(ScanTarget.FromFile));
        IReporter reporter = format.ToLowerInvariant() switch
        {
            "sarif" => new SarifReporter(),
            "console" => new ConsoleReporter(!noColor && outputPath is null),
            _ => throw new ArgumentException($"Unknown format '{format}'. Supported: console, sarif")
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
        var threshold = ParseThreshold(failOn);
        return threshold is { } value && report.CountAtOrAbove(value) > 0 ? 1 : 0;
    }

    public static Severity? ParseThreshold(string failOn) => failOn.ToLowerInvariant() switch
    {
        "never" => null,
        "note" => Severity.Note,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => Severity.High
    };
}
