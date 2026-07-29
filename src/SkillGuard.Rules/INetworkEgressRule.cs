using SkillGuard.Core;

namespace SkillGuard.Rules;

public interface INetworkEgressRule
{
    IReadOnlySet<string> AllowedHosts { get; }
    IEnumerable<Finding> Scan(ScanTarget target);
}
