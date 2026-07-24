using Xunit;
using System;
using System.IO;
using System.Text;
using System.Globalization;
using SkillGuard.Core;

namespace SkillGuard.Tests;

public class ConsoleReporterTests
{
    [Fact]
    public void Write_EmptyReport_DoesNotThrow()
    {
        // Arrange
        var reporter = new ConsoleReporter();
        var output = new StringWriter();
        var report = new ScanReport(Array.Empty<Finding>(), 0, 0, TimeSpan.Zero);

        // Act
        reporter.Write(report, output);

        // Assert
        Assert.Empty(output.ToString());
    }

    [Fact]
    public void Write_NullReport_ThrowsArgumentNullException()
    {
        // Arrange
        var reporter = new ConsoleReporter();
        var output = new StringWriter();
        var report = null as ScanReport;

        // Act and Assert
        Assert.Throws<ArgumentNullException>(() => reporter.Write(report, output));
    }

    [Fact]
    public void Write_NullOutput_ThrowsArgumentNullException()
    {
        // Arrange
        var reporter = new ConsoleReporter();
        var output = null as TextWriter;
        var report = new ScanReport(Array.Empty<Finding>(), 0, 0, TimeSpan.Zero);

        // Act and Assert
        Assert.Throws<ArgumentNullException>(() => reporter.Write(report, output));
    }

    [Fact]
    public void SeverityLabel_Critical_ReturnsExpectedString()
    {
        // Act
        var result = ConsoleReporter.SeverityLabel(Severity.Critical);

        // Assert
        Assert.Equal("CRITICAL", result);
    }

    [Fact]
    public void SeverityLabel_Low_ReturnsExpectedString()
    {
        // Act
        var result = ConsoleReporter.SeverityLabel(Severity.Low);

        // Assert
        Assert.Equal("LOW", result);
    }

    [Fact]
    public void SeverityLabel_Note_ReturnsExpectedString()
    {
        // Act
        var result = ConsoleReporter.SeverityLabel((Severity)8);

        // Assert
        Assert.Equal("NOTE", result);
    }
}
