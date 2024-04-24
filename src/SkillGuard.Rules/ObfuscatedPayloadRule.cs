using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class ObfuscatedPayloadRule : RegexScanRule
{
    public override string Id => "SG004";
    public override string Name => "ObfuscatedPayload";
    public override string Description => "Detects base64/hex-decoded execution and other obfuscation techniques";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.Obfuscation;
    public override string? Remediation => "Encoded payloads that get decoded and executed cannot be reviewed; inline the plain command";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"base64\s+(-d|--decode|-D)\s*\|?\s*((ba)?sh|python3?|node|eval)?", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Base64 decode step, often used to hide payloads"),
        new(new Regex(@"echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64", RegexOptions.Compiled),
            "Long inline base64 blob piped to decoder", Severity.Critical),
        new(new Regex(@"eval\s*[\(""'`]?\s*\$\(", RegexOptions.Compiled),
            "Eval of dynamically constructed command output"),
        new(new Regex(@"\bxxd\s+-r\b|\bFromBase64String\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Hex or base64 reversal into executable content", Severity.Medium),
        new(new Regex(@"\$\{[A-Za-z_]+:?[0-9]*:[0-9]+\}\$\{[A-Za-z_]+", RegexOptions.Compiled),
            "String-slicing variable assembly used to evade pattern matching", Severity.Medium),
        new(new Regex(@"powershell[^\n]*\s-(e|enc|encodedcommand)\s", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "PowerShell encoded command execution", Severity.Critical)
    ];
}
