using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class NetworkEgressRule : IScanRule, INetworkEgressRule, IEquatable<NetworkEgressRule>
{
    public string Id => NetworkEgressRuleConstants.Id;
    public string Name => NetworkEgressRuleConstants.Name;
    public string Description => NetworkEgressRuleConstants.Description;
    public Severity DefaultSeverity => Severity.Medium;
    public FindingCategory Category => FindingCategory.NetworkEgress;

    public static readonly IReadOnlySet<string> DefaultAllowedHosts = new HashSet<string>(NetworkEgressRuleConstants.DefaultAllowedHosts, StringComparer.OrdinalIgnoreCase);

    private static readonly Regex UrlPattern = new(NetworkEgressRuleConstants.UrlPattern, RegexOptions.Compiled);
    private static readonly Regex RawIpPattern = new(NetworkEgressRuleConstants.RawIpPattern, RegexOptions.Compiled);
    private static readonly Regex NetClientPattern = new(NetworkEgressRuleConstants.NetClientPattern, RegexOptions.Compiled);

    public IReadOnlySet<string> AllowedHosts { get; }

    public NetworkEgressRule(IEnumerable<string>? additionalAllowedHosts = null)
    {
        var hosts = new HashSet<string>(DefaultAllowedHosts, StringComparer.OrdinalIgnoreCase);
        if (additionalAllowedHosts is not null) hosts.UnionWith(additionalAllowedHosts);
        AllowedHosts = hosts;
    }

    public IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ScanCore(target);
    }

    private IEnumerable<Finding> ScanCore(ScanTarget target)
    {
        for (var i = 0; i < target.Lines.Length; i++)
        {
            var line = target.Lines[i];
            foreach (Match match in UrlPattern.Matches(line))
            {
                var host = match.Groups[1].Value;
                if (AllowedHosts.Contains(host)) continue;
                var isRawIp = RawIpPattern.IsMatch(match.Value);
                var invokesClient = NetClientPattern.IsMatch(line);
                var severity = (isRawIp, invokesClient) switch
                {
                    (true, _) => Severity.High,
                    (false, true) => Severity.Medium,
                    _ => Severity.Low
                };
                var reason = isRawIp
                    ? string.Format(NetworkEgressRuleConstants.ReasonRawIp, host)
                    : invokesClient
                        ? string.Format(NetworkEgressRuleConstants.ReasonClientInvocation, host)
                        : string.Format(NetworkEgressRuleConstants.ReasonReference, host);
                yield return new Finding(Id, Name, severity, Category, reason,
                    SourceLocation.At(target.FilePath, i + 1, match.Index + 1, match.Length),
                    line.Trim().Length > NetworkEgressRuleConstants.MaxReasonLength ? line.Trim()[..NetworkEgressRuleConstants.MaxReasonLength] : line.Trim())
                { Remediation = NetworkEgressRuleConstants.RemediationMessage };
            }
        }
    }

    public bool Equals(NetworkEgressRule? other)
    {
        if (ReferenceEquals(null, other)) return false;
        if (ReferenceEquals(this, other)) return true;

        return Id == other.Id &&
               Name == other.Name &&
               Description == other.Description &&
               DefaultSeverity == other.DefaultSeverity &&
               Category == other.Category &&
               AllowedHosts.SetEquals(other.AllowedHosts);
    }

    public override bool Equals(object? obj) => Equals(obj as NetworkEgressRule);

    public override int GetHashCode()
    {
        return HashCode.Combine(Id, Name, Description, DefaultSeverity, Category, AllowedHosts);
    }

    public static bool operator ==(NetworkEgressRule? left, NetworkEgressRule? right) => Equals(left, right);

    public static bool operator !=(NetworkEgressRule? left, NetworkEgressRule? right) => !Equals(left, right);
}
