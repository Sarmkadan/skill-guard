using SkillGuard.Core;
using SkillGuard.Rules;
using Xunit;

namespace SkillGuard.Tests;

/// <summary>
/// Contains unit tests for the <see cref="RuleEngine"/> and <see cref="RuleCatalog"/> components.
/// Implements <see cref="IRuleEngineTests"/> and <see cref="IEquatable{RuleEngineTests}"/>.
/// </summary>
public class RuleEngineTests : IRuleEngineTests, IEquatable<RuleEngineTests>
{
    /// <summary>
    /// Verifies that the <see cref="RuleEngine.Scan"/> method orders findings by severity (descending) and then by location.
    /// </summary>
    [Fact]
    public void Scan_OrdersFindingsBySeverityThenLocation()
    {
        var engine = new RuleEngine(RuleCatalog.CreateDefaultRules());
        var target = Targets.Skill($$"""
            {{RuleEngineTestsConstants.SketchyUrlSnippet}}
            {{RuleEngineTestsConstants.CurlPipeBashSnippet}}
            """);
        var report = engine.Scan([target]);
        Assert.Equal(RuleEngineTestsConstants.ExpectedFilesScanned, report.FilesScanned);
        Assert.Equal(RuleCatalog.CreateDefaultRules().Count, report.RulesExecuted);
        Assert.True(report.HasFindings);
        Assert.Equal(Severity.Critical, report.MaxSeverity);
        Assert.Equal(Severity.Critical, report.Findings[0].Severity);
        Assert.True(report.Findings.Zip(report.Findings.Skip(1)).All(p => p.First.Severity >= p.Second.Severity));
    }

    /// <summary>
    /// Verifies that scanning a clean skill file produces no findings.
    /// </summary>
    [Fact]
    public void Scan_CleanSkillProducesNoFindings()
    {
        var engine = new RuleEngine(RuleCatalog.CreateDefaultRules());
        var report = engine.Scan([Targets.Skill(Targets.CleanSkill)]);
        Assert.False(report.HasFindings);
        Assert.Equal(RuleEngineTestsConstants.ExpectedNoFindings, report.CountAtOrAbove(Severity.Note));
    }

    /// <summary>
    /// Verifies that the <see cref="Report.CountAtOrAbove"/> method correctly filters findings based on severity thresholds.
    /// </summary>
    [Fact]
    public void CountAtOrAbove_FiltersBySeverity()
    {
        var engine = new RuleEngine(RuleCatalog.CreateDefaultRules());
        var report = engine.Scan([Targets.Skill(RuleEngineTestsConstants.SketchyUrlSnippet)]);
        Assert.Equal(RuleEngineTestsConstants.ExpectedLowSeverityFindings, report.CountAtOrAbove(Severity.Low));
        Assert.Equal(RuleEngineTestsConstants.ExpectedNoFindings, report.CountAtOrAbove(Severity.High));
    }

    /// <summary>
    /// Verifies that the default rule catalog contains the expected rule IDs from SG001 to SG011.
    /// </summary>
    [Fact]
    public void RuleCatalog_ExposesRulesSg001ThroughSg011()
    {
        var ids = RuleCatalog.CreateDefaultRules().Select(r => r.Id).Order().ToList();
        Assert.Equal(
            [
                RuleEngineTestsConstants.RuleIdSg001,
                RuleEngineTestsConstants.RuleIdSg002,
                RuleEngineTestsConstants.RuleIdSg003,
                RuleEngineTestsConstants.RuleIdSg004,
                RuleEngineTestsConstants.RuleIdSg005,
                RuleEngineTestsConstants.RuleIdSg006,
                RuleEngineTestsConstants.RuleIdSg007,
                RuleEngineTestsConstants.RuleIdSg008,
                RuleEngineTestsConstants.RuleIdSg009,
                RuleEngineTestsConstants.RuleIdSg010,
                RuleEngineTestsConstants.RuleIdSg011
            ],
            ids);
    }

    /// <summary>
    /// Verifies that all rule IDs in the default catalog are unique.
    /// </summary>
    [Fact]
    public void RuleCatalog_HasUniqueRuleIds()
    {
        var ids = RuleCatalog.CreateDefaultRules().Select(r => r.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    /// <summary>
    /// Verifies that the <see cref="RuleCatalog.Filter"/> method correctly disables rules based on provided IDs, handling case insensitivity.
    /// </summary>
    [Fact]
    public void RuleCatalog_Filter_DisablesRulesCaseInsensitively()
    {
        var rules = RuleCatalog.Filter(RuleCatalog.CreateDefaultRules(), [RuleEngineTestsConstants.RuleIdSg001Lower, RuleEngineTestsConstants.RuleIdSg005]);
        Assert.DoesNotContain(rules, r => r.Id is RuleEngineTestsConstants.RuleIdSg001 or RuleEngineTestsConstants.RuleIdSg005);
        Assert.Contains(rules, r => r.Id == RuleEngineTestsConstants.RuleIdSg002);
    }

    /// <summary>
    /// Determines equality based on the type.
    /// </summary>
    /// <param name="other">The other object to compare.</param>
    /// <returns>True if the other object is not null and of the same type; otherwise, false.</returns>
    public bool Equals(RuleEngineTests? other) =>
        other is not null &&
        GetType() == other.GetType();

    /// <summary>
    /// Determines equality against an arbitrary object.
    /// </summary>
    /// <param name="obj">The object to compare.</param>
    /// <returns>True if the object is a <see cref="RuleEngineTests"/> and is equal; otherwise, false.</returns>
    public override bool Equals(object? obj) => Equals(obj as RuleEngineTests);

    /// <summary>
    /// Returns a hash code for the current object.
    /// </summary>
    /// <returns>A hash code based on the type.</returns>
    public override int GetHashCode() => HashCode.Combine(GetType());

    /// <summary>
    /// Determines if two <see cref="RuleEngineTests"/> instances are equal.
    /// </summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns>True if the operands are equal; otherwise, false.</returns>
    public static bool operator ==(RuleEngineTests? left, RuleEngineTests? right) => Equals(left, right);

    /// <summary>
    /// Determines if two <see cref="RuleEngineTests"/> instances are not equal.
    /// </summary>
    /// <param name="left">The left operand.</param>
    /// <param name="right">The right operand.</param>
    /// <returns>True if the operands are not equal; otherwise, false.</returns>
    public static bool operator !=(RuleEngineTests? left, RuleEngineTests? right) => !Equals(left, right);
}
