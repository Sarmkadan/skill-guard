using System.Text.RegularExpressions;

namespace SkillGuard.Core;

/// <summary>
/// Defines a pattern to be matched by a RegexScanRule, including the message to report
/// and an optional severity override.
/// </summary>
/// <param name="Pattern">The regular expression pattern to match</param>
/// <param name="Message">The finding message to report when this pattern matches</param>
/// <param name="SeverityOverride">
/// Optional severity override. When null, the rule's <see cref="RegexScanRule.DefaultSeverity"/> is used.
/// When specified, this severity takes precedence over the rule's default severity.
/// </param>
/// <remarks>
/// Severity Resolution Contract:
/// <list type="bullet">
/// <item><description>If <see cref="SeverityOverride"/> is set, it is used as the finding's severity</description></item>
/// <item><description>If <see cref="SeverityOverride"/> is null, the rule's <see cref="RegexScanRule.DefaultSeverity"/> is used</description></item>
/// <item><description>The resolved severity is set exactly once in the Finding constructor</description></item>
/// <item><description>This same severity value is used by RiskScore aggregation</description></item>
/// </list>
/// </remarks>
public sealed class PatternDefinition : IEquatable<PatternDefinition>
{
    public Regex Pattern { get; }
    public string Message { get; }
    public Severity? SeverityOverride { get; }

    public PatternDefinition(Regex pattern, string message, Severity? severityOverride = null)
    {
        Pattern = pattern;
        Message = message;
        SeverityOverride = severityOverride;
    }

    public bool Equals(PatternDefinition? other)
    {
        if (other is null) return false;
        return Pattern == other.Pattern &&
               Message == other.Message &&
               SeverityOverride == other.SeverityOverride;
    }

    public override bool Equals(object? obj)
    {
        return obj is PatternDefinition other && Equals(other);
    }

    public override int GetHashCode()
    {
        return System.HashCode.Combine(Pattern, Message, SeverityOverride);
    }

    public static bool operator ==(PatternDefinition? left, PatternDefinition? right)
    {
        return EqualityComparer<PatternDefinition>.Default.Equals(left, right);
    }

    public static bool operator !=(PatternDefinition? left, PatternDefinition? right)
    {
        return !(left == right);
    }
}

/// <summary>
/// Abstract base class for rules that scan files using regular expressions.
/// Provides standardized severity resolution through <see cref="SeverityResolution"/>.
/// </summary>
/// <remarks>
/// Severity Resolution Flow:
/// <list type="number">
/// <item><description>Rule declares <see cref="DefaultSeverity"/></description></item>
/// <item><description>PatternDefinition declares optional <see cref="PatternDefinition.SeverityOverride"/></description></item>
/// <item><description><see cref="SeverityResolution.Resolve"/> computes: PatternDefinition.SeverityOverride ?? DefaultSeverity</description></item>
/// <item><description>Finding is created with the resolved severity</description></item>
/// <item><description>RiskScore aggregates using the same Finding.Severity value</description></item>
/// </list>
///
/// This ensures there is no divergence where the Finding shows one severity while
/// RiskScore counts it under a different severity due to inconsistent resolution timing.
/// </remarks>
public abstract class RegexScanRule : IScanRule
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract string Description { get; }
    public abstract Severity DefaultSeverity { get; }
    public abstract FindingCategory Category { get; }
    public virtual string? Remediation => null;
    protected abstract IReadOnlyList<PatternDefinition> Patterns { get; }
    protected virtual bool AppliesTo(ScanTarget target) => true;

    /// <summary>
    /// Gets the maximum time a pattern may spend matching a single line before it is abandoned.
    /// Scanned files are attacker-controlled, so this bound stops catastrophic backtracking from hanging the scan.
    /// </summary>
    protected virtual TimeSpan MatchTimeout => TimeSpan.FromSeconds(1);

    private IReadOnlyList<BoundedPattern>? _boundedPatterns;

    /// <summary>
    /// Gets the patterns rebuilt with <see cref="MatchTimeout"/>, created once per rule instance.
    /// </summary>
    private IReadOnlyList<BoundedPattern> BoundedPatterns =>
        _boundedPatterns ??= [.. Patterns.Select(p => new BoundedPattern(p, new Regex(p.Pattern.ToString(), p.Pattern.Options, MatchTimeout)))];

    public virtual IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ScanCore(target);
    }

    protected virtual IEnumerable<Finding> ScanCore(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!AppliesTo(target)) yield break;
        var bounded = BoundedPatterns;
        var timedOut = new bool[bounded.Count];
        for (var i = 0; i < target.Lines.Length; i++)
        {
            var line = target.Lines[i];
            for (var p = 0; p < bounded.Count; p++)
            {
                if (timedOut[p]) continue;
                var (definition, regex) = bounded[p];
                if (!TryMatch(regex, line, out var matches))
                {
                    timedOut[p] = true;
                    yield return CreateTimeoutFinding(target, i + 1, line);
                    continue;
                }

                foreach (var match in matches)
                {
                    var resolvedSeverity = SeverityResolution.Resolve(definition, DefaultSeverity);
                    var finding = new Finding(
                        Id,
                        Name,
                        resolvedSeverity,
                        Category,
                        definition.Message,
                        SourceLocation.At(target.FilePath, i + 1, match.Index + 1, match.Length),
                        Snippet(line)
                    )
                    {
                        Remediation = Remediation
                    };

                    SeverityResolution.Validate(finding);
                    yield return finding;
                }
            }
        }
    }

    /// <summary>
    /// Collects all matches of <paramref name="regex"/> in <paramref name="input"/> without yielding inside the try block.
    /// </summary>
    /// <param name="regex">The timeout-bounded regex to run.</param>
    /// <param name="input">The line to match against.</param>
    /// <param name="matches">The matches found, or an empty list when the timeout was reached.</param>
    /// <returns><c>true</c> if matching finished within <see cref="MatchTimeout"/>; otherwise <c>false</c>.</returns>
    private static bool TryMatch(Regex regex, string input, out List<Match> matches)
    {
        try
        {
            matches = regex.Matches(input).Cast<Match>().ToList();
            return true;
        }
        catch (RegexMatchTimeoutException)
        {
            matches = [];
            return false;
        }
    }

    /// <summary>
    /// Creates the diagnostic reported when a pattern exceeds <see cref="MatchTimeout"/> on a line.
    /// A timeout on attacker-authored input is treated as a High-severity signal, so the scan fails closed.
    /// </summary>
    /// <param name="target">The file being scanned.</param>
    /// <param name="lineNumber">The 1-based line on which the pattern timed out.</param>
    /// <param name="line">The text of that line.</param>
    /// <returns>A High-severity <see cref="Finding"/> describing the timeout.</returns>
    private Finding CreateTimeoutFinding(ScanTarget target, int lineNumber, string line)
    {
        var finding = new Finding(
            Id,
            Name,
            Severity.High,
            Category,
            $"A pattern exceeded the {MatchTimeout.TotalMilliseconds:0} ms match timeout and was skipped for the rest of this file; the input may be crafted to cause catastrophic backtracking",
            SourceLocation.At(target.FilePath, lineNumber, 1, 1),
            Snippet(line));

        SeverityResolution.Validate(finding);
        return finding;
    }

    private static string Snippet(string line)
    {
        var trimmed = line.Trim();
        return trimmed.Length > 200 ? trimmed[..200] : trimmed;
    }

    private sealed record BoundedPattern(PatternDefinition Definition, Regex Regex);
}
