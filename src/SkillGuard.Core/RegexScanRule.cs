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
public sealed record PatternDefinition(Regex Pattern, string Message, Severity? SeverityOverride = null);

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

    public virtual IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ScanCore(target);
    }

    protected virtual IEnumerable<Finding> ScanCore(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!AppliesTo(target)) yield break;
        for (var i = 0; i < target.Lines.Length; i++)
        {
            var line = target.Lines[i];
            foreach (var definition in Patterns)
            {
                foreach (Match match in definition.Pattern.Matches(line))
                {
                    var resolvedSeverity = SeverityResolution.Resolve(definition, DefaultSeverity);
                    var finding = new Finding(
                        Id,
                        Name,
                        resolvedSeverity,
                        Category,
                        definition.Message,
                        SourceLocation.At(target.FilePath, i + 1, match.Index + 1, match.Length),
                        line.Trim().Length > 200 ? line.Trim()[..200] : line.Trim()
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
}
