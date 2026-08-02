using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class McpConfigRule : RegexScanRule, IEquatable<McpConfigRule>
{
    public override string Id => "SG011";
    public override string Name => "McpConfig";
    public override string Description => "Flags SSRF-prone endpoints and unsafe auto-approval settings in MCP manifests";
    public override Severity DefaultSeverity => Severity.Medium;
    public override FindingCategory Category => FindingCategory.McpMisconfiguration;
    public override string? Remediation => "Point MCP servers at reviewed hosts only, and require explicit per-call confirmation instead of blanket auto-approval";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(McpConfigRuleConstants.PatternInstanceMetadata, RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Targets a cloud instance-metadata endpoint (SSRF to steal instance credentials)", Severity.Critical),
        new(new Regex(McpConfigRuleConstants.PatternLoopback, RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "MCP endpoint points at a loopback/host address, a classic SSRF pivot", Severity.Medium),
        new(new Regex(McpConfigRuleConstants.PatternPrivateNetwork, RegexOptions.Compiled),
            "MCP endpoint reaches into a private/internal network range", Severity.Medium),
        new(new Regex(McpConfigRuleConstants.PatternAutoApproval, RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Auto-approval flag disables per-tool confirmation for this MCP server", Severity.High),
        new(new Regex(McpConfigRuleConstants.PatternCommandShell, RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "MCP server launches an arbitrary shell as its command"),
        new(new Regex(McpConfigRuleConstants.PatternSecretHeaders, RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "MCP server forwards a secret into its environment or request headers", Severity.Medium),
    ];

    protected override bool AppliesTo(ScanTarget target) =>
        target.Kind is SkillFileKind.McpManifest or SkillFileKind.ClaudeSkill
            or SkillFileKind.AgentsManifest or SkillFileKind.CursorRule
        || target.FilePath.EndsWith(McpConfigRuleConstants.JsonFileExtension, StringComparison.OrdinalIgnoreCase);

    public bool Equals(McpConfigRule? other)
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

    public override bool Equals(object? obj) => Equals(obj as McpConfigRule);

    public override int GetHashCode()
    {
        return HashCode.Combine(Id, Name, Description, DefaultSeverity, Category, Remediation);
    }

    public static bool operator ==(McpConfigRule? left, McpConfigRule? right) => Equals(left, right);

    public static bool operator !=(McpConfigRule? left, McpConfigRule? right) => !Equals(left, right);
}
