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
    Obfuscation
}

public sealed record SourceLocation(string FilePath, int Line, int Column, int EndColumn)
{
    public static SourceLocation At(string filePath, int line, int column, int length) =>
        new(filePath, line, column, column + Math.Max(length, 1));
    public override string ToString() => $"{FilePath}:{Line}:{Column}";
}

public sealed record Finding(
    string RuleId,
    string RuleName,
    Severity Severity,
    FindingCategory Category,
    string Message,
    SourceLocation Location,
    string Snippet)
{
    public string? Remediation { get; init; }
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
