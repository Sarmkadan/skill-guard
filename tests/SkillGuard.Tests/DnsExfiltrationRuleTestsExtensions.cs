using System;
using System.Collections.Generic;
using System.Linq;
using SkillGuard.Core;
using SkillGuard.Rules;

namespace SkillGuard.Tests;

/// <summary>
/// Extension methods for <see cref="DnsExfiltrationRuleTests"/> that provide
/// reusable helpers for scanning lines and inspecting findings.
/// </summary>
public static class DnsExfiltrationRuleTestsExtensions
{
    /// <summary>
    /// Scans the supplied <paramref name="line"/> using <see cref="DnsExfiltrationRule"/>
    /// and returns a read‑only list of <see cref="Finding"/> objects.
    /// </summary>
    /// <param name="test">The test instance (used only for null‑checking).</param>
    /// <param name="line">The line of skill content to scan.</param>
    /// <returns>A read‑only list of findings produced by the rule.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="test"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="line"/> is <c>null</c> or empty.</exception>
    public static IReadOnlyList<Finding> Scan(this DnsExfiltrationRuleTests test, string line)
    {
        ArgumentNullException.ThrowIfNull(test);
        ArgumentException.ThrowIfNullOrEmpty(line);
        var rule = new DnsExfiltrationRule();
        var target = Targets.Skill(line);
        return rule.Scan(target).ToList().AsReadOnly();
    }

    /// <summary>
    /// Determines whether the first finding for <paramref name="line"/> has
    /// <see cref="Severity.Critical"/> severity.
    /// </summary>
    /// <param name="test">The test instance.</param>
    /// <param name="line">The line to scan.</param>
    /// <returns><c>true</c> if a critical finding exists; otherwise <c>false</c>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="test"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="line"/> is <c>null</c> or empty.</exception>
    public static bool IsCritical(this DnsExfiltrationRuleTests test, string line) =>
        test.Scan(line).FirstOrDefault()?.Severity == Severity.Critical;

    /// <summary>
    /// Counts the number of findings produced for the given <paramref name="line"/>.
    /// </summary>
    /// <param name="test">The test instance.</param>
    /// <param name="line">The line to scan.</param>
    /// <returns>The total number of findings.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="test"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="line"/> is <c>null</c> or empty.</exception>
    public static int CountFindings(this DnsExfiltrationRuleTests test, string line) =>
        test.Scan(line).Count;

    /// <summary>
    /// Retrieves the first <see cref="Finding"/> for <paramref name="line"/>, or <c>null</c> if none exist.
    /// </summary>
    /// <param name="test">The test instance.</param>
    /// <param name="line">The line to scan.</param>
    /// <returns>The first finding, or <c>null</c> when no findings are produced.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="test"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="line"/> is <c>null</c> or empty.</exception>
    public static Finding? FirstFinding(this DnsExfiltrationRuleTests test, string line) =>
        test.Scan(line).FirstOrDefault();
}
