using System.Diagnostics;
using System.Text.RegularExpressions;
using SkillGuard.Core;
using Xunit;

namespace SkillGuard.Tests;

/// <summary>
/// Contains tests verifying that <see cref="RegexScanRule"/> bounds every pattern with a match timeout.
/// </summary>
public class RegexScanRuleTests
{
    /// <summary>
    /// A rule whose only pattern backtracks catastrophically on a long run of 'a' followed by a non-matching character.
    /// </summary>
    private sealed class CatastrophicRule : RegexScanRule
    {
        public override string Id => "SG999";
        public override string Name => "Catastrophic";
        public override string Description => "Test-only rule with a catastrophic-backtracking pattern";
        public override Severity DefaultSeverity => Severity.Low;
        public override FindingCategory Category => FindingCategory.PromptInjection;
        protected override TimeSpan MatchTimeout => TimeSpan.FromMilliseconds(200);

        protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
        [
            new(new Regex(@"^(a+)+$", RegexOptions.Compiled), "Nested quantifier matched"),
        ];
    }

    /// <summary>
    /// Verifies that a pathological input produces a timeout diagnostic instead of hanging the scan.
    /// </summary>
    [Fact]
    public void Reports_TimeoutFinding_Instead_Of_Hanging_On_Pathological_Input()
    {
        var content = new string('a', 60) + "!";
        var target = new ScanTarget("/repo/evil/SKILL.md", content, SkillFileKind.ClaudeSkill);

        var stopwatch = Stopwatch.StartNew();
        var finding = Assert.Single(new CatastrophicRule().Scan(target));
        stopwatch.Stop();

        Assert.Equal("SG999", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("/repo/evil/SKILL.md", finding.Location.FilePath);
        Assert.Equal(1, finding.Location.Line);
        Assert.Contains("match timeout", finding.Message);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(30), $"Scan took {stopwatch.Elapsed}, timeout did not bound matching.");
    }

    /// <summary>
    /// Verifies that a pattern still produces normal findings when matching completes within the timeout.
    /// </summary>
    [Fact]
    public void Still_Reports_Matches_When_Within_Timeout()
    {
        var target = new ScanTarget("/repo/ok/SKILL.md", "aaaa", SkillFileKind.ClaudeSkill);

        var finding = Assert.Single(new CatastrophicRule().Scan(target));

        Assert.Equal("SG999", finding.RuleId);
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("Nested quantifier matched", finding.Message);
    }
}
