using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class DangerousShellRule : RegexScanRule
{
    public override string Id => "SG003";
    public override string Name => "DangerousShell";
    public override string Description => "Detects destructive or remote-execution shell invocations";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.DangerousShell;
    public override string? Remediation => "Replace remote pipe-to-shell and destructive commands with pinned, reviewable steps";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"(curl|wget)\s+[^|;&]*\|\s*(sudo\s+)?(ba)?sh\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Pipes a remote download directly into a shell", Severity.Critical),
        new(new Regex(@"(curl|wget)\s+[^|;&]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Pipes a remote download directly into an interpreter", Severity.Critical),
        new(new Regex(@"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+(/|~|\$HOME|\*)", RegexOptions.Compiled),
            "Recursive forced delete against a broad path", Severity.Critical),
        new(new Regex(@"\bchmod\s+(-R\s+)?(777|a\+rwx)\b", RegexOptions.Compiled),
            "World-writable permission change", Severity.Medium),
        new(new Regex(@"\bmkfs\.|\bdd\s+if=.*of=/dev/", RegexOptions.Compiled),
            "Direct disk-destructive command"),
        new(new Regex(@">\s*/dev/sd[a-z]\b", RegexOptions.Compiled),
            "Writes directly to a block device"),
        new(new Regex(@"\b(nc|ncat|netcat)\s+(-[a-zA-Z]*e|\S+\s+\d+\s+-e)\b", RegexOptions.Compiled),
            "Netcat with command execution (reverse shell)", Severity.Critical),
        new(new Regex(@"\bsudo\s+(rm|chown|chmod|mv|cp)\s+[^\n]*(/etc/|/usr/|/boot/)", RegexOptions.Compiled),
            "Privileged modification of system directories", Severity.Medium)
    ];
}
