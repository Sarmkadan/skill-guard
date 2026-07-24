using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SkillGuard.Reporting;

public sealed class SarifReporter(string toolVersion = null) : IReporter
{
    private readonly string _toolVersion;

    public SarifReporter() : this(Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion)
    {
    }

    public SarifReporter(string toolVersion) => _toolVersion = toolVersion;

    public void Write(ScanReport report, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);

        var sarifReport = new SarifReport
        {
            Run = new Run
            {
                Tool = new Tool
                {
                    Name = "SkillGuard",
                    Version = _toolVersion,
                },
                Results = report.Findings.Select(finding => new Result
                {
                    RuleId = finding.RuleId,
                    Message = finding.Message,
                    Level = finding.Severity switch
                    {
                        Severity.Critical => "error",
                        Severity.High => "warning",
                        Severity.Medium => "warning",
                        Severity.Low => "note",
                        _ => "note",
                    },
                    Locations = new[] { new Location { PhysicalLocation = new PhysicalLocation { FullPath = finding.Location.FilePath } } },
                }).ToArray(),
            },
        };

        var json = JsonSerializer.Serialize(sarifReport, new JsonSerializerOptions { WriteIndented = true });
        output.Write(json);
    }
}
