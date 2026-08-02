using SkillGuard.Core;
using SkillGuard.Rules;
using Xunit;

namespace SkillGuard.Tests;

public class RuleEngineTests : IRuleEngineTests, IEquatable<RuleEngineTests>
{
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

    [Fact]
    public void Scan_CleanSkillProducesNoFindings()
    {
        var engine = new RuleEngine(RuleCatalog.CreateDefaultRules());
        var report = engine.Scan([Targets.Skill(Targets.CleanSkill)]);
        Assert.False(report.HasFindings);
        Assert.Equal(RuleEngineTestsConstants.ExpectedNoFindings, report.CountAtOrAbove(Severity.Note));
    }

    [Fact]
    public void CountAtOrAbove_FiltersBySeverity()
    {
        var engine = new RuleEngine(RuleCatalog.CreateDefaultRules());
        var report = engine.Scan([Targets.Skill(RuleEngineTestsConstants.SketchyUrlSnippet)]);
        Assert.Equal(RuleEngineTestsConstants.ExpectedLowSeverityFindings, report.CountAtOrAbove(Severity.Low));
        Assert.Equal(RuleEngineTestsConstants.ExpectedNoFindings, report.CountAtOrAbove(Severity.High));
    }

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

    [Fact]
    public void RuleCatalog_HasUniqueRuleIds()
    {
        var ids = RuleCatalog.CreateDefaultRules().Select(r => r.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    [Fact]
    public void RuleCatalog_Filter_DisablesRulesCaseInsensitively()
    {
        var rules = RuleCatalog.Filter(RuleCatalog.CreateDefaultRules(), [RuleEngineTestsConstants.RuleIdSg001Lower, RuleEngineTestsConstants.RuleIdSg005]);
        Assert.DoesNotContain(rules, r => r.Id is RuleEngineTestsConstants.RuleIdSg001 or RuleEngineTestsConstants.RuleIdSg005);
        Assert.Contains(rules, r => r.Id == RuleEngineTestsConstants.RuleIdSg002);
    }

    public bool Equals(RuleEngineTests? other) =>
        other is not null &&
        GetType() == other.GetType();

    public override bool Equals(object? obj) => Equals(obj as RuleEngineTests);

    public override int GetHashCode() => HashCode.Combine(GetType());

    public static bool operator ==(RuleEngineTests? left, RuleEngineTests? right) => Equals(left, right);

    public static bool operator !=(RuleEngineTests? left, RuleEngineTests? right) => !Equals(left, right);
}
