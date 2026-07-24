using System.Diagnostics.CodeAnalysis;

namespace SkillGuard.Core;

/// <summary>
/// Provides standardized severity resolution for rule findings.
/// This class ensures that severity is resolved exactly once at Finding-construction time
/// and provides a consistent contract across all rule implementations.
/// </summary>
/// <remarks>
/// Severity Resolution Contract:
/// 1. PatternDefinition.SeverityOverride: When set, takes precedence over rule's DefaultSeverity
/// 2. PatternDefinition.SeverityOverride == null: Use the rule's DefaultSeverity
/// 3. Rules without PatternDefinition: Must provide Severity directly in Finding constructor
/// 4. RiskScore aggregation: Always uses Finding.Severity (already resolved)
///
/// This ensures that the Finding.Severity value is the single source of truth
/// and matches what gets aggregated into RiskScore.Counts.
/// </remarks>
public static class SeverityResolution
{
    /// <summary>
    /// Resolves the severity for a pattern-based finding using the standardized contract.
    /// </summary>
    /// <param name="patternDefinition">The pattern definition (may be null if no override is specified)</param>
    /// <param name="ruleDefaultSeverity">The rule's default severity to use when no override is specified</param>
    /// <returns>The resolved severity to use for the Finding</returns>
    /// <exception cref="ArgumentNullException">Thrown if ruleDefaultSeverity is null</exception>
    /// <remarks>
    /// Resolution Logic:
    /// <list type="number">
    /// <item><description>If <paramref name="patternDefinition"/> is not null AND has <see cref="PatternDefinition.SeverityOverride"/> set, use that override</description></item>
    /// <item><description>Otherwise, use <paramref name="ruleDefaultSeverity"/></description></item>
    /// </list>
    /// This ensures consistent severity resolution across all RegexScanRule implementations.
    /// </remarks>
    public static Severity Resolve(PatternDefinition? patternDefinition, Severity ruleDefaultSeverity)
    {
        ArgumentNullException.ThrowIfNull(ruleDefaultSeverity);

        return patternDefinition?.SeverityOverride ?? ruleDefaultSeverity;
    }

    /// <summary>
    /// Validates that a Finding has a valid severity value.
    /// </summary>
    /// <param name="finding">The finding to validate</param>
    /// <exception cref="ArgumentNullException">Thrown if finding is null</exception>
    /// <exception cref="ArgumentException">Thrown if finding.Severity is not a valid enum value</exception>
    /// <remarks>
    /// This method provides defensive validation to ensure that the Finding.Severity
    /// (which should already be resolved via <see cref="Resolve"/>) is a valid enum value.
    /// It acts as a safety check in case the Finding record constructor is bypassed or
    /// if there are any edge cases in severity resolution.
    /// </remarks>
    public static void Validate(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        // Severity is a required non-nullable property on Finding, so this is primarily
        // a defensive check that would catch issues if the record constructor is bypassed
        if (!Enum.IsDefined(typeof(Severity), finding.Severity))
        {
            throw new ArgumentException(
                $"Finding has invalid Severity value: {finding.Severity}. " +
                "Severity must be one of: Note, Low, Medium, High, Critical.",
                nameof(finding));
        }
    }

    /// <summary>
    /// Gets the weight multiplier for a severity level used in RiskScore calculation.
    /// </summary>
    /// <param name="severity">The severity level</param>
    /// <returns>The weight multiplier for the severity</returns>
    /// <exception cref="ArgumentNullException">Thrown if severity is null</exception>
    /// <remarks>
    /// Weight values are used by <see cref="RiskScore"/> to calculate the overall risk score:
    /// <list type="bullet">
    /// <item><description><see cref="Severity.Critical"/> = 40 points</description></item>
    /// <item><description><see cref="Severity.High"/> = 15 points</description></item>
    /// <item><description><see cref="Severity.Medium"/> = 5 points</description></item>
    /// <item><description><see cref="Severity.Low"/> = 1 point</description></item>
    /// <item><description><see cref="Severity.Note"/> = 0 points</description></item>
    /// </list>
    /// These weights ensure that higher-severity findings contribute more to the overall risk score.
    /// </remarks>
    public static int GetWeight(Severity severity)
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
}
