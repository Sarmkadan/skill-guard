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

/// <summary>
/// Represents a region of a source file using 1-based line and column numbers.
/// The end column is exclusive, matching SARIF region semantics.
/// </summary>
/// <param name="FilePath">The path of the file that contains the region.</param>
/// <param name="Line">The line where the region starts.</param>
/// <param name="Column">The column where the region starts.</param>
/// <param name="EndLine">The line where the region ends. Equal to <paramref name="Line"/> for single-line regions.</param>
/// <param name="EndColumn">The column just past the end of the region, on <paramref name="EndLine"/>.</param>
public sealed record SourceLocation(string FilePath, int Line, int Column, int EndLine, int EndColumn)
{
    /// <summary>
    /// Initializes a single-line region, so <see cref="EndLine"/> defaults to <paramref name="line"/>.
    /// </summary>
    /// <param name="filePath">The path of the file that contains the region.</param>
    /// <param name="line">The line where the region starts and ends.</param>
    /// <param name="column">The column where the region starts.</param>
    /// <param name="endColumn">The column just past the end of the region.</param>
    public SourceLocation(string filePath, int line, int column, int endColumn)
        : this(filePath, line, column, line, endColumn)
    {
    }

    /// <summary>
    /// Gets a value indicating whether the region spans more than one line.
    /// </summary>
    public bool IsMultiLine => EndLine > Line;

    /// <summary>
    /// Gets the position as <c>line:column</c>, or <c>line-endLine:column</c> for multi-line regions.
    /// </summary>
    public string PositionLabel => IsMultiLine ? $"{Line}-{EndLine}:{Column}" : $"{Line}:{Column}";

    /// <summary>
    /// Creates a single-line region for a match of <paramref name="length"/> characters.
    /// </summary>
    /// <param name="filePath">The path of the file that contains the region.</param>
    /// <param name="line">The line where the match starts.</param>
    /// <param name="column">The column where the match starts.</param>
    /// <param name="length">The length of the match. Values below 1 are treated as 1.</param>
    /// <returns>A single-line <see cref="SourceLocation"/>.</returns>
    public static SourceLocation At(string filePath, int line, int column, int length) =>
        new(filePath, line, column, column + Math.Max(length, 1));

    /// <summary>
    /// Creates a region from a character offset and length within <paramref name="content"/>,
    /// which may span multiple lines. Use this for matches found by scanning the whole file.
    /// </summary>
    /// <param name="filePath">The path of the file that contains the region.</param>
    /// <param name="content">The full text of the file the offset refers to.</param>
    /// <param name="index">The zero-based character offset where the match starts.</param>
    /// <param name="length">The length of the match in characters. Values below 1 are treated as 1.</param>
    /// <returns>A <see cref="SourceLocation"/> covering the match, clamped to the end of <paramref name="content"/>.</returns>
    /// <exception cref="ArgumentException">Thrown if <paramref name="filePath"/> is null or empty.</exception>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="content"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="index"/> is negative or past the end of <paramref name="content"/>, or if <paramref name="length"/> is negative.</exception>
    public static SourceLocation FromOffset(string filePath, string content, int index, int length)
    {
        ArgumentException.ThrowIfNullOrEmpty(filePath);
        ArgumentNullException.ThrowIfNull(content);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(index, content.Length);
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        var (line, column) = PositionOf(content, index);
        var end = Math.Min(index + Math.Max(length, 1), content.Length);
        var (endLine, endColumn) = PositionOf(content, end);
        return new(filePath, line, column, endLine, endColumn);
    }

    /// <summary>
    /// Computes the 1-based line and column of the character offset <paramref name="offset"/>.
    /// </summary>
    private static (int Line, int Column) PositionOf(string content, int offset)
    {
        var prefix = content.AsSpan(0, offset);
        var lastBreak = prefix.LastIndexOf('\n');
        return (prefix.Count('\n') + 1, offset - lastBreak);
    }

    /// <inheritdoc/>
    public override string ToString() => $"{FilePath}:{PositionLabel}";
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
