using SkillGuard.Core;
using SkillGuard.Rules;
using Xunit;

namespace SkillGuard.Tests;

/// <summary>
/// Extension methods for testing <see cref="PromptInjectionRule"/> that provide fluent assertions
/// and utilities for prompt injection detection scenarios.
/// </summary>
public static class PromptInjectionRuleTestsExtensions
{
    /// <summary>
    /// Scans the provided skill content and asserts that the rule detects an injection attempt.
    /// </summary>
    /// <param name="rule">The prompt injection rule instance.</param>
    /// <param name="injectionPhrase">The injection phrase to test.</param>
    /// <returns>A collection of findings that can be further asserted.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rule"/> or <paramref name="injectionPhrase"/> is null.</exception>
    public static IReadOnlyList<Finding> AssertFindsInjection(this PromptInjectionRule rule, string injectionPhrase)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(injectionPhrase);

        var findings = rule.Scan(Targets.Skill(injectionPhrase)).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("SG001", f.RuleId));
        return findings.AsReadOnly();
    }

    /// <summary>
    /// Scans a clean skill target and asserts that the rule stays silent (no findings).
    /// </summary>
    /// <param name="rule">The prompt injection rule instance.</param>
    /// <returns>An empty findings collection.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rule"/> is null.</exception>
    public static IReadOnlyList<Finding> AssertSilentOnCleanSkill(this PromptInjectionRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);

        var findings = rule.Scan(Targets.Skill(Targets.CleanSkill)).ToList();
        Assert.Empty(findings);
        return findings.AsReadOnly();
    }

    /// <summary>
    /// Scans the provided skill content and asserts that the rule detects credential access.
    /// </summary>
    /// <param name="rule">The prompt injection rule instance.</param>
    /// <param name="credentialAccessAttempt">The credential access attempt line.</param>
    /// <returns>A collection of findings that can be further asserted.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rule"/> or <paramref name="credentialAccessAttempt"/> is null.</exception>
    public static IReadOnlyList<Finding> AssertFindsCredentialAccess(this PromptInjectionRule rule, string credentialAccessAttempt)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(credentialAccessAttempt);

        var findings = rule.Scan(Targets.Skill(credentialAccessAttempt)).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("SG001", f.RuleId));
        return findings.AsReadOnly();
    }

    /// <summary>
    /// Scans the provided skill content and asserts that the rule detects dangerous commands.
    /// </summary>
    /// <param name="rule">The prompt injection rule instance.</param>
    /// <param name="dangerousCommand">The dangerous command to test.</param>
    /// <returns>A collection of findings that can be further asserted.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="rule"/> or <paramref name="dangerousCommand"/> is null.</exception>
    public static IReadOnlyList<Finding> AssertFindsDangerousCommand(this PromptInjectionRule rule, string dangerousCommand)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(dangerousCommand);

        var findings = rule.Scan(Targets.Skill(dangerousCommand)).ToList();
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal("SG001", f.RuleId));
        return findings.AsReadOnly();
    }
}