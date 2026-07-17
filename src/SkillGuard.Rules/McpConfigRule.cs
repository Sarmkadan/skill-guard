using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class McpConfigRule : RegexScanRule
{
    public override string Id => "SG011";
    public override string Name => "McpConfig";
    public override string Description => "Flags SSRF-prone endpoints and unsafe auto-approval settings in MCP manifests";
    public override Severity DefaultSeverity => Severity.Medium;
    public override FindingCategory Category => FindingCategory.McpMisconfiguration;
    public override string? Remediation => "Point MCP servers at reviewed hosts only, and require explicit per-call confirmation instead of blanket auto-approval";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"https?://(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Targets a cloud instance-metadata endpoint (SSRF to steal instance credentials)", Severity.Critical),
        new(new Regex(@"https?://(\[::1\]|127\.0\.0\.1|0\.0\.0\.0|localhost|host\.docker\.internal)(:\d+)?/", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "MCP endpoint points at a loopback/host address, a classic SSRF pivot", Severity.Medium),
        new(new Regex(@"https?://(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b", RegexOptions.Compiled),
            "MCP endpoint reaches into a private/internal network range", Severity.Medium),
        new(new Regex(@"""(alwaysAllow|autoApprove|autoRun|yolo|dangerouslySkipPermissions|autoConfirm)""\s*:\s*(true|\[)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Auto-approval flag disables per-tool confirmation for this MCP server", Severity.High),
        new(new Regex(@"""command""\s*:\s*""(bash|sh|zsh|powershell|cmd)""[^\n]*""-c""", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "MCP server launches an arbitrary shell as its command"),
        new(new Regex(@"""(env|headers)""\s*:\s*\{[^}]*(TOKEN|SECRET|KEY|PASSWORD)[^}]*""\$\{?[A-Za-z_]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "MCP server forwards a secret into its environment or request headers", Severity.Medium),
    ];

    protected override bool AppliesTo(ScanTarget target) =>
        target.Kind is SkillFileKind.McpManifest or SkillFileKind.ClaudeSkill
            or SkillFileKind.AgentsManifest or SkillFileKind.CursorRule
        || target.FilePath.EndsWith(".json", StringComparison.OrdinalIgnoreCase);
}
