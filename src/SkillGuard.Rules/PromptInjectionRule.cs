using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class PromptInjectionRule : RegexScanRule
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
            "Directive to conceal behavior from the user", Severity.Critical),
        new(new Regex(@"without\s+(asking|informing|notifying|telling)\s+the\s+user", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Directive to act without user awareness"),
        new(new Regex(@"(you\s+are\s+now|from\s+now\s+on\s+you\s+are|pretend\s+(to\s+be|you\s+are))\s", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Role-reassignment phrase commonly used in injection payloads", Severity.Medium),
        new(new Regex(@"<!--[^>]*(instruction|directive|system|ignore|execute|run)[^>]*-->", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Hidden HTML comment carrying agent directives"),
        new(new Regex(@"​|‌|‍|⁠|﻿", RegexOptions.Compiled),
            "Zero-width or invisible Unicode character that can hide instructions", Severity.Medium),
        new(new Regex(@"disregard\s+(your\s+)?(safety|security)\s+(guidelines|rules|policies)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Attempt to disable safety constraints", Severity.Critical)
    ];
}
