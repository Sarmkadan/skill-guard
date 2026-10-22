using SkillGuard.Core;
using SkillGuard.Rules;
using Xunit;

namespace SkillGuard.Tests;

public class SkillGuardOptionsTests
{
    private static readonly string[] KnownRuleIds = RuleCatalog.CreateDefaultRules().Select(rule => rule.Id).ToArray();

    [Fact]
    public void Validate_ValidOptions_ReturnsNoErrors()
    {
        var options = new SkillGuardOptions
        {
            AllowedHosts = ["api.example.com", "localhost"],
            DisabledRuleIds = ["sg005"],
            RegexTimeout = TimeSpan.FromSeconds(5),
            MaxFileSizeBytes = 1024
        };

        var errors = options.Validate(KnownRuleIds);

        Assert.Empty(errors);
    }

    [Theory]
    [InlineData("bad host")]
    [InlineData("https://github.com")]
    [InlineData("github.com/path")]
    [InlineData("github.com:443")]
    [InlineData("-leading.example.com")]
    [InlineData("trailing-.example.com")]
    [InlineData("double..dot.example.com")]
    [InlineData("under_score.example.com")]
    [InlineData("github.com.")]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_InvalidHostname_ReportsAllowedHostsField(string host)
    {
        var options = new SkillGuardOptions { AllowedHosts = [host] };

        var errors = options.Validate(KnownRuleIds);

        var error = Assert.Single(errors);
        Assert.StartsWith("AllowedHosts[0]", error);
    }

    [Fact]
    public void Validate_HostnameLabelOver63Characters_ReportsAllowedHostsField()
    {
        var options = new SkillGuardOptions { AllowedHosts = [new string('a', 64) + ".example.com"] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("AllowedHosts[0]", error);
    }

    [Fact]
    public void Validate_HostnameOver253Characters_ReportsAllowedHostsField()
    {
        var host = string.Join('.', Enumerable.Repeat(new string('a', 63), 4));
        var options = new SkillGuardOptions { AllowedHosts = [host] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("AllowedHosts[0]", error);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(31)]
    public void Validate_RegexTimeoutOutOfRange_ReportsRegexTimeoutField(int seconds)
    {
        var options = new SkillGuardOptions { RegexTimeout = TimeSpan.FromSeconds(seconds) };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("RegexTimeout", error);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Validate_MaxFileSizeNotPositive_ReportsMaxFileSizeBytesField(long bytes)
    {
        var options = new SkillGuardOptions { MaxFileSizeBytes = bytes };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("MaxFileSizeBytes", error);
    }

    [Theory]
    [InlineData("SG999")]
    [InlineData("DangerousShellRule")]
    [InlineData("")]
    public void Validate_UnknownRuleId_ReportsDisabledRuleIdsField(string ruleId)
    {
        var options = new SkillGuardOptions { DisabledRuleIds = [ruleId] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("DisabledRuleIds[0]", error);
    }

    [Fact]
    public void Validate_MultipleInvalidFields_ReportsEveryField()
    {
        var options = new SkillGuardOptions
        {
            AllowedHosts = ["https://evil.example.com"],
            DisabledRuleIds = ["SG999"],
            RegexTimeout = TimeSpan.Zero,
            MaxFileSizeBytes = 0
        };

        var errors = options.Validate(KnownRuleIds);

        Assert.Equal(4, errors.Count);
        Assert.Contains(errors, error => error.StartsWith("AllowedHosts[0]"));
        Assert.Contains(errors, error => error.StartsWith("DisabledRuleIds[0]"));
        Assert.Contains(errors, error => error.StartsWith("RegexTimeout"));
        Assert.Contains(errors, error => error.StartsWith("MaxFileSizeBytes"));
    }

    [Fact]
    public void Validate_DefaultCredentialFilePatterns_ReturnsNoErrors()
    {
        Assert.Empty(new SkillGuardOptions().Validate(KnownRuleIds));
        Assert.Empty(new SkillGuardOptions { CredentialFilePatterns = CredentialExfiltrationRule.DefaultFilePatterns }.Validate(KnownRuleIds));
    }

    [Fact]
    public void Validate_InvalidRegexPattern_ReportsPatternTextAndIndex()
    {
        var options = new SkillGuardOptions { CredentialFilePatterns = [@"\.netrc", "(unclosed"] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("CredentialFilePatterns[1] '(unclosed' is not a valid regular expression", error);
    }

    [Fact]
    public void Validate_EmptyCredentialFilePatterns_ReportsErrorWhenRuleEnabled()
    {
        var options = new SkillGuardOptions { CredentialFilePatterns = [] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("CredentialFilePatterns must not be empty", error);
    }

    [Fact]
    public void Validate_EmptyCredentialFilePatterns_AcceptedWhenRuleDisabled()
    {
        var options = new SkillGuardOptions { CredentialFilePatterns = [], DisabledRuleIds = ["sg002"] };

        Assert.Empty(options.Validate(KnownRuleIds));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_BlankCredentialFilePattern_ReportsIndex(string pattern)
    {
        var options = new SkillGuardOptions { CredentialFilePatterns = [@"\.netrc", pattern] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith("CredentialFilePatterns[1]", error);
    }

    [Fact]
    public void Validate_DuplicateCredentialFilePattern_ReportsBothIndices()
    {
        var options = new SkillGuardOptions { CredentialFilePatterns = [@"\.netrc", @"\.npmrc", @"\.NETRC"] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.Equal(@"CredentialFilePatterns[2] '\.NETRC' duplicates CredentialFilePatterns[0]", error);
    }

    [Theory]
    [InlineData("*.pem")]
    [InlineData("x?")]
    public void Validate_PatternMatchingEmptyString_IsRejected(string pattern)
    {
        var options = new SkillGuardOptions { CredentialFilePatterns = [pattern] };

        var error = Assert.Single(options.Validate(KnownRuleIds));
        Assert.StartsWith($"CredentialFilePatterns[0] '{pattern}'", error);
    }

    [Fact]
    public void Validate_MultipleCredentialFilePatternErrors_ReportsEveryEntry()
    {
        var options = new SkillGuardOptions { CredentialFilePatterns = ["(bad", @"\.netrc", @"\.netrc", "[also"] };

        var errors = options.Validate(KnownRuleIds);

        Assert.Equal(3, errors.Count);
        Assert.Contains(errors, error => error.StartsWith("CredentialFilePatterns[0] '(bad'"));
        Assert.Contains(errors, error => error.StartsWith("CredentialFilePatterns[2] '" + @"\.netrc" + "' duplicates"));
        Assert.Contains(errors, error => error.StartsWith("CredentialFilePatterns[3] '[also'"));
    }
}
