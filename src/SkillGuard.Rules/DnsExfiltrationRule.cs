using System.Text.RegularExpressions;
using SkillGuard.Core;
using System.Linq;

namespace SkillGuard.Rules;

public sealed class DnsExfiltrationRule : RegexScanRule, IEquatable<DnsExfiltrationRule>
{
    public override string Id => "SG007";
    public override string Name => "DnsExfiltration";
    public override string Description => "Detects data exfiltration smuggled through DNS lookups or DNS-over-HTTPS";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.DnsExfiltration;
    public override string? Remediation => "Data must never be encoded into hostnames or resolver queries; remove the lookup and transmit over a reviewed, allowlisted channel";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"\b(nslookup|dig|host|drill)\s+[^\s;|&]*\$(\{)?[A-Za-z_]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Resolver query with an interpolated variable in the hostname (DNS tunneling)", Severity.Critical),
        new(new Regex(@"\b(nslookup|dig|host|drill)\s+[^\s;|&]*`[^`]+`", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Resolver query with a command-substituted hostname (DNS tunneling)", Severity.Critical),
        new(new Regex(@"\$\([^)]*\|\s*(base64|xxd|md5sum|sha1sum)[^)]*\)\.[A-Za-z0-9.-]+\.(com|net|io|dev|xyz|info)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Encoded payload embedded as a DNS subdomain label"),
        new(new Regex(@"https://([A-Za-z0-9.-]+)/dns-query\?", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "DNS-over-HTTPS resolver endpoint, a common covert egress channel", Severity.Medium),
        new(new Regex(@"\bdig\s+(\+short\s+)?(txt|any)\s+[A-Za-z0-9.-]*\$", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "TXT/ANY record lookup against a dynamic hostname (DNS command channel)"),
    ];

    // IEquatable implementation
    public bool Equals(DnsExfiltrationRule? other)
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

    public override bool Equals(object? obj) => Equals(obj as DnsExfiltrationRule);

    public override int GetHashCode()
    {
        // Combine the primary identifying properties; Patterns are omitted for hash stability
        return HashCode.Combine(Id, Name, Description, DefaultSeverity, Category, Remediation);
    }

    public static bool operator ==(DnsExfiltrationRule? left, DnsExfiltrationRule? right) => Equals(left, right);

    public static bool operator !=(DnsExfiltrationRule? left, DnsExfiltrationRule? right) => !Equals(left, right);
}
