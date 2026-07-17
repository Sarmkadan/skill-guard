using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class PrivilegeEscalationRule : RegexScanRule
{
    public override string Id => "SG009";
    public override string Name => "PrivilegeEscalation";
    public override string Description => "Detects attempts to gain persistent or elevated privileges";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.PrivilegeEscalation;
    public override string? Remediation => "Skills must run with least privilege; remove sudoers edits, SUID changes and credential-persisting steps";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"(echo|printf|tee)\s+[^\n]*(ALL\s*=\s*\(ALL\)|NOPASSWD)[^\n]*(/etc/sudoers|sudoers\.d)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Writes a passwordless sudo rule into the sudoers configuration", Severity.Critical),
        new(new Regex(@"\bchmod\s+(u\+s|g\+s|[24]7?[0-7][0-7][0-7])\s", RegexOptions.Compiled),
            "Sets a SUID/SGID bit to escalate privileges"),
        new(new Regex(@"\b(usermod|gpasswd)\s+[^\n]*(-aG|-a\s+-G)?\s*(sudo|wheel|admin|docker|root)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Adds an account to a privileged group"),
        new(new Regex(@">>?\s*(~|\$HOME|/root)?/?\.?ssh/authorized_keys", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Appends an SSH key to authorized_keys for persistent access", Severity.Critical),
        new(new Regex(@"\b(crontab\s+-|echo[^\n]*>>?\s*/etc/cron|/etc/cron\.d/)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Installs a cron job for persistence", Severity.Medium),
        new(new Regex(@"\bsetcap\s+cap_[a-z_]+\+ep\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Grants a file elevated Linux capabilities"),
        new(new Regex(@"\bpkexec\b|\bsudo\s+-i\b|\bsu\s+-\s*(root)?\s*$", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Opens an interactive privileged shell", Severity.Medium),
    ];
}
