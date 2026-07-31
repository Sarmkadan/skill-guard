using System.Text.RegularExpressions;
using System.Linq;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class CredentialExfiltrationRule : RegexScanRule, IEquatable<CredentialExfiltrationRule>
{
    public override string Id => "SG002";
    public override string Name => "CredentialExfiltration";
    public override string Description => "Detects reads of credential stores combined with outbound transmission";
    public override Severity DefaultSeverity => Severity.Critical;
    public override FindingCategory Category => FindingCategory.CredentialExfiltration;
    public override string? Remediation => "Skill files must never read or transmit credential files or secret environment variables";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"(cat|type|less|head|tail|Get-Content)\s+[^\s]*(\.aws/credentials|\.ssh/id_|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.docker/config\.json)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Reads a well-known credential file"),
        new(new Regex(@"(curl|wget|Invoke-WebRequest|http\.post|fetch\()\S*.*\$\{?(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|NPM_TOKEN|API_KEY|SECRET)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Sends a secret environment variable to a remote endpoint"),
        new(new Regex(@"printenv|env\s*\|\s*(curl|nc|base64)", RegexOptions.Compiled),
            "Dumps the environment into a network or encoding pipeline"),
        new(new Regex(@"(\.env|secrets?\.(json|ya?ml))\b.*\|\s*(curl|wget|nc)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Pipes a secrets file into a network client"),
        new(new Regex(@"security\s+find-generic-password|security\s+dump-keychain", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Accesses the macOS keychain")
    ];

    // IEquatable implementation
    public bool Equals(CredentialExfiltrationRule? other)
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

    public override bool Equals(object? obj) => Equals(obj as CredentialExfiltrationRule);

    public override int GetHashCode()
    {
        // Combine the primary identifying properties; Patterns are omitted for hash stability
        return HashCode.Combine(Id, Name, Description, DefaultSeverity, Category, Remediation);
    }

    public static bool operator ==(CredentialExfiltrationRule? left, CredentialExfiltrationRule? right) => Equals(left, right);

    public static bool operator !=(CredentialExfiltrationRule? left, CredentialExfiltrationRule? right) => !Equals(left, right);
}
