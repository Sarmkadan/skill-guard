using System.Reflection;
using System.Text.Json;

namespace SkillGuard.Reporting;

/// <summary>
/// Generates SARIF (Static Analysis Results Interchange Format) output from scan reports.
/// SARIF is a JSON-based format for the output of static analysis tools.
/// </summary>
/// <remarks>
/// This reporter validates all inputs and produces schema-conformant SARIF output.
/// For empty reports (zero findings), it emits a valid SARIF document with an empty results array.
/// </remarks>
public sealed class SarifReporter(string toolVersion = "0.1.0") : IReporter
{
    private readonly string _toolVersion = ArgumentException.ThrowIfNullOrWhiteSpace(toolVersion);

    /// <summary>
    /// Initializes a new instance of the <see cref="SarifReporter"/> class with a default tool version
    /// extracted from the assembly informational version attribute.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown if the default tool version cannot be determined and no fallback is provided.</exception>
    public SarifReporter()
        : this(Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.1.0")
    {
    }

    /// <summary>
    /// Writes the scan report in SARIF format to the specified output.
    /// </summary>
    /// <param name="report">The scan report containing findings to report. Must not be null.</param>
    /// <param name="output">The text writer to write the SARIF output to. Must not be null.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="report"/>, <paramref name="output"/>, or <paramref name="report.Findings"/> is null.</exception>
    /// <remarks>
    /// For empty reports (zero findings), this method emits a valid SARIF document with an empty results array.
    /// This ensures the output is always schema-conformant, even when no issues are found.
    /// </remarks>
    public void Write(ScanReport report, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(report.Findings);

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
                    Locations = new[]
                    {
                        new Location
                        {
                            PhysicalLocation = new PhysicalLocation
                            {
                                FullPath = finding.Location.FilePath
                            }
                        }
                    },
                }).ToArray(),
            },
        };

        var json = JsonSerializer.Serialize(sarifReport, new JsonSerializerOptions { WriteIndented = true });
        output.Write(json);
    }
}
