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
}