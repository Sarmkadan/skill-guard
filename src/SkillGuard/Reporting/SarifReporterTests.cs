using System.Reflection;
using Xunit;

namespace SkillGuard.Reporting.Tests;

public class SarifReporterTests
{
    [Fact]
    public void DefaultToolVersionMatchesAssemblyVersion()
    {
        // Arrange
        var assembly = typeof(SarifReporter).Assembly;
        var assemblyVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        // Act
        var reporter = new SarifReporter();
        var toolVersion = reporter._toolVersion;

        // Assert
        Assert.Equal(assemblyVersion, toolVersion);
    }
}
