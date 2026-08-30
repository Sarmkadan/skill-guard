using SkillGuard.Core;

namespace SkillGuard.Rules;

public static class RuleCatalog
{
    public static IReadOnlyList<IScanRule> CreateDefaultRules(IEnumerable<string>? allowedHosts = null)
    {
        return
        [
            new PromptInjectionRule(),
            new CredentialExfiltrationRule(),
            new DangerousShellRule(),
            new ObfuscatedPayloadRule(),
            new NetworkEgressRule(allowedHosts),
            new UnreviewedPayloadRule(),
            new DnsExfiltrationRule(),
            new IndirectInjectionRule(),
            new PrivilegeEscalationRule(),
            new SandboxEscapeRule(),
            new McpConfigRule(),
            new McpManifestRule(),
            new DecodedPayloadRule()
        ];
    }

    public static IReadOnlyList<IScanRule> Filter(IReadOnlyList<IScanRule> rules, IReadOnlyCollection<string> disabledRuleIds)
    {
        ArgumentNullException.ThrowIfNull(rules);
        ArgumentNullException.ThrowIfNull(disabledRuleIds);

        return disabledRuleIds.Count == 0
            ? rules
            : rules.Where(r => !disabledRuleIds.Contains(r.Id, StringComparer.OrdinalIgnoreCase)).ToList();
    }
}
