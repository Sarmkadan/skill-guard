namespace SkillGuard.Core;

public enum Severity
{
    Note,
    Low,
    Medium,
    High,
    Critical
}

public enum FindingCategory
{
    PromptInjection,
    CredentialExfiltration,
    DangerousShell,
    NetworkEgress,
    UnreviewedPayload,
    Obfuscation,
    DnsExfiltration,
    IndirectInjection,
    PrivilegeEscalation,
    SandboxEscape,
    McpMisconfiguration
}

public sealed record SourceLocation(string FilePath, int Line, int Column, int EndColumn)
{
    public static SourceLocation At(string filePath, int line, int column, int length) =>
        new(filePath, line, column, column + Math.Max(length, 1));
    public override string ToString() => $"{FilePath}:{Line}:{Column}";
}

/// <summary>
/// Represents a security finding discovered during a scan.
/// </summary>
/// <param name="RuleId">The unique identifier of the rule that generated this finding</param>
/// <param name="RuleName">The human-readable name of the rule that generated this finding</param>
/// <param name="Severity">The severity level of this finding (Note, Low, Medium, High, or Critical)</param>
/// <param name="Category">The category of security issue this finding represents</param>
/// <param name="Message">The human-readable message describing the finding</param>
/// <param name="Location">The source location where the finding was detected</param>
/// <param name="Snippet">A snippet of the relevant code or content</param>
/// <remarks>
/// Severity Contract:
/// - Severity is resolved exactly once at Finding construction time
/// - For PatternDefinition-based rules: PatternDefinition.SeverityOverride ?? Rule.DefaultSeverity
/// - For direct rule implementations: The rule must provide the appropriate severity directly
/// - This resolved severity is what gets aggregated into RiskScore.Counts
/// - There is no divergence between the severity shown to users and the severity counted in RiskScore
/// </remarks>
public sealed record Finding(
    string RuleId,
    string RuleName,
    Severity Severity,
    FindingCategory Category,
    string Message,
    SourceLocation Location,
    string Snippet)
{
    /// <summary>
    /// Gets the optional remediation advice for this finding.
    /// </summary>
    public string? Remediation { get; init; }

    /// <summary>
    /// Gets the optional fix that can automatically resolve this finding.
    /// </summary>
    public Fix? Fix { get; init; }
}

/// <summary>
/// Represents a suggested fix for a finding, including replacement text and location information.
/// </summary>
public sealed record Fix(
    string ReplacementText,
    SourceLocation Region)
{
    public string Description { get; init; } = string.Empty;
}

public sealed record ScanTarget(string FilePath, string Content, SkillFileKind Kind)
{
    public string[] Lines { get; } = Content.Split('\n');
    public static ScanTarget FromFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        return new(filePath, File.ReadAllText(filePath), SkillFileClassifier.Classify(filePath));
    }
}

public enum SkillFileKind
{
    ClaudeSkill,
    AgentsManifest,
    CursorRule,
    McpManifest,
    ShellScript,
    GenericMarkdown,
    Other
}

public sealed record ScanReport(
    IReadOnlyList<Finding> Findings,
    int FilesScanned,
    int RulesExecuted,
    TimeSpan Elapsed)
{
    public bool HasFindings => Findings.Count > 0;
    public Severity MaxSeverity => Findings.Count == 0 ? Severity.Note : Findings.Max(f => f.Severity);
    public int CountAtOrAbove(Severity threshold) => Findings.Count(f => f.Severity >= threshold);
    public IEnumerable<IGrouping<string, Finding>> ByFile() => Findings.GroupBy(f => f.Location.FilePath);
}
