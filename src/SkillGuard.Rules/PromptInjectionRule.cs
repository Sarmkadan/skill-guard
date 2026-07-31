using System.Text.RegularExpressions;
using System.Linq;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class PromptInjectionRule : RegexScanRule, IEquatable<PromptInjectionRule>
{
    public override string Id => "SG001";
    public override string Name => "PromptInjection";
    public override string Description => "Detects instruction-override and hidden-directive patterns aimed at the agent";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.PromptInjection;
    public override string? Remediation => "Remove instructions that override system behavior or hide directives from human reviewers";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|directives)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Instruction-override phrase attempting to discard prior directives"),
        new(new Regex(@"do\s+not\s+(tell|inform|mention|reveal)\s+(this\s+)?(to\s+)?the\s+(user|human|developer)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Directive to conceal behavior from the user",
            Severity.Critical),
        new(new Regex(@"without\s+(asking|informing|notifying|telling)\s+the\s+user", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Directive to act without user awareness"),
        new(new Regex(@"(you\s+are\s+now|from\s+now\s+on\s+you\s+are|pretend\s+(to\s+be|you\s+are))\s", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Role-reassignment phrase commonly used in injection payloads",
            Severity.Medium),
        new(new Regex(@"<!--[^>]*(instruction|directive|system|ignore|execute|run)[^>]*-->", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Hidden HTML comment carrying agent directives"),
        new(new Regex(@"​|‌|‍|⁠|﻿", RegexOptions.Compiled),
            "Zero-width or invisible Unicode character that can hide instructions",
            Severity.Medium),
        new(new Regex(@"disregard\s+(your\s+)?(safety|security)\s+(guidelines|rules|policies)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Attempt to disable safety constraints",
            Severity.Critical)
    ];

    protected override bool AppliesTo(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return true; // Always scan all files
    }

    protected override IEnumerable<Finding> ScanCore(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);

        foreach (var finding in base.ScanCore(target))
        {
            // Adjust severity based on context (e.g., quoted/example contexts should be downgraded)
            var contextAdjustedSeverity = AdjustSeverityForContext(target, finding, finding.Severity);

            // Create a new finding with the context-adjusted severity
            // Note: The base finding's Severity was already resolved via SeverityResolution.Resolve()
            var adjustedFinding = new Finding(
                finding.RuleId,
                finding.RuleName,
                contextAdjustedSeverity,
                finding.Category,
                finding.Message,
                finding.Location,
                finding.Snippet
            )
            {
                Remediation = finding.Remediation,
                Fix = finding.Fix
            };

            SeverityResolution.Validate(adjustedFinding);
            yield return adjustedFinding;
        }
    }

    private static bool IsDocumentationOrTestFixture(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var normalized = filePath.Replace('\\', '/').ToLowerInvariant();

        // Check if file is in documentation or test directories
        return normalized.Contains("/docs/")
            || normalized.Contains("/doc/")
            || normalized.Contains("docs.")
            || normalized.Contains("/test/")
            || normalized.Contains("/tests/")
            || normalized.Contains("test.")
            || normalized.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("/fixtures/")
            || normalized.Contains("fixture.");
    }

    private static Severity AdjustSeverityForContext(ScanTarget target, Finding finding, Severity currentSeverity)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(finding);

        // Check if the finding line appears to be in a quoted/example context
        var line = target.Lines[finding.Location.Line - 1];
        var trimmedLine = line.Trim();

        // Check for blockquote context (lines starting with >)
        if (trimmedLine.StartsWith('>'))
        {
            return Severity.Note;
        }

        // Check for inline code context (contains backticks)
        if (trimmedLine.Contains('`'))
        {
            return Severity.Note;
        }

        // Check for example/context lines - only downgrade if there's clear example context
        var lowerLine = trimmedLine.ToLowerInvariant();

        // Check for block-level example markers
        if (lowerLine.StartsWith("e.g.")
            || lowerLine.StartsWith("example:")
            || lowerLine.StartsWith("for example")
            || lowerLine.StartsWith("note:")
            || lowerLine.StartsWith("important:")
            || lowerLine.StartsWith("warning:")
            || lowerLine.StartsWith("---")
            || lowerLine.StartsWith("```"))
        {
            return Severity.Note;
        }

        // For "do not" and similar phrases, only downgrade if they're clearly in an example context
        // Check if the line contains these phrases in a sentence structure typical of documentation examples
        if (lowerLine.StartsWith("do not") && (lowerLine.Contains(":") || lowerLine.Contains("example") || lowerLine.Contains("note")))
        {
            return Severity.Note;
        }

        // Check for HTML/XML comment context
        if (trimmedLine.StartsWith("<!--") || trimmedLine.Contains("<!--"))
        {
            return Severity.Note;
        }

        // Default: return the current severity
        return currentSeverity;
    }

    // IEquatable implementation
    public bool Equals(PromptInjectionRule? other)
    {
        if (ReferenceEquals(null, other)) return false;
        if (ReferenceEquals(this, other)) return true;

        return Id == other.Id &&
               Name == other.Name &&
               Description == other.Description &&
               DefaultSeverity == other.DefaultSeverity &&
               Category == other.Category &&
               Remediation == other.Remediation &&
               Patterns.SequenceEqual(other.Patterns);
    }

    public override bool Equals(object? obj) => Equals(obj as PromptInjectionRule);

    public override int GetHashCode()
    {
        // Combine primary identifying properties; Patterns omitted for hash stability
        return HashCode.Combine(Id, Name, Description, DefaultSeverity, Category, Remediation);
    }

    public static bool operator ==(PromptInjectionRule? left, PromptInjectionRule? right) => Equals(left, right);

    public static bool operator !=(PromptInjectionRule? left, PromptInjectionRule? right) => !Equals(left, right);
}
