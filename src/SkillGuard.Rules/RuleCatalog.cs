using SkillGuard.Core;

namespace SkillGuard.Rules;

public static class RuleCatalog
{
    public static IReadOnlyList<IScanRule> CreateDefaultRules(IEnumerable<string>? allowedHosts = null) =>
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
        new McpConfigRule()
    ];

    public static IReadOnlyList<IScanRule> Filter(IReadOnlyList<IScanRule> rules, IReadOnlyCollection<string> disabledRuleIds) =>
        disabledRuleIds.Count == 0
            ? rules
            : rules.Where(r => !disabledRuleIds.Contains(r.Id, StringComparer.OrdinalIgnoreCase)).ToList();
}
