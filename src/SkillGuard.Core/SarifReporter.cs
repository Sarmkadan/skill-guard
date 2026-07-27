using System.Reflection;
using System.Text.Json;

namespace SkillGuard.Core;

/// <summary>
/// Generates SARIF (Static Analysis Results Interchange Format) output from scan reports.
/// SARIF is a JSON-based format for the output of static analysis tools.
/// </summary>
/// <remarks>
/// This reporter validates all inputs and produces schema-conformant SARIF output.
/// For empty reports (zero findings), it emits a valid SARIF document with an empty results array.
/// </remarks>
public sealed class SarifReporter : IReporter, ISarifReporter
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };
    private readonly string _toolVersion;

    /// <summary>
    /// Initializes a new instance of the <see cref="SarifReporter"/> class with a default tool version.
    /// </summary>
    public SarifReporter()
        : this(Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.1.0")
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SarifReporter"/> class with a custom tool version.
    /// </summary>
    /// <param name="toolVersion">The tool version to include in the SARIF output. Must not be null or whitespace.</param>
    /// <exception cref="ArgumentException">Thrown if <paramref name="toolVersion"/> is null or whitespace.</exception>
    public SarifReporter(string toolVersion)
    {
        _toolVersion = toolVersion;
        ArgumentException.ThrowIfNullOrWhiteSpace(_toolVersion);
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

        var rules = report.Findings
            .GroupBy(f => f.RuleId)
            .Select(g => new
            {
                id = g.Key,
                name = g.First().RuleName,
                shortDescription = new { text = g.First().Message },
                defaultConfiguration = new { level = ToSarifLevel(g.Max(f => f.Severity)) }
            })
            .ToArray();

        var results = report.Findings.Select(f => new
        {
            ruleId = f.RuleId,
            level = ToSarifLevel(f.Severity),
            message = new { text = f.Message },
            locations = new[]
            {
                new
                {
                    physicalLocation = new
                    {
                        artifactLocation = new { uri = f.Location.FilePath.Replace('\\', '/') },
                        region = new
                        {
                            startLine = f.Location.Line,
                            startColumn = f.Location.Column,
                            endColumn = f.Location.EndColumn,
                            snippet = new { text = f.Snippet }
                        }
                    }
                }
            },
            fixes = GetFixes(f)
        }).ToArray();

        var score = RiskScore.From(report);
        var document = new
        {
            version = "2.1.0",
            schema = "https://json.schemastore.org/sarif-2.1.0.json",
            runs = new[]
            {
                new
                {
                    tool = new
                    {
                        driver = new
                        {
                            name = "skill-guard",
                            version = _toolVersion,
                            informationUri = "https://github.com/Sarmkadan/skill-guard",
                            rules
                        }
                    },
                    results,
                    properties = new { riskScore = score.Points, riskGrade = score.Grade.ToString() }
                }
            }
        };
        var json = JsonSerializer.Serialize(document, Options).Replace("\"schema\":", "\"$schema\":");
        output.WriteLine(json);
    }

    /// <summary>
    /// Extracts fix information for a finding if available.
    /// </summary>
    /// <param name="finding">The finding to extract fixes for.</param>
    /// <returns>A fixes array if the finding has a fix, otherwise null.</returns>
    private static object? GetFixes(Finding finding)
    {
        if (finding.Fix is null)
        {
            return null;
        }

        return new[]
        {
            new
            {
                description = new
                {
                    text = string.IsNullOrEmpty(finding.Fix.Description)
                        ? "Suggested fix for this finding"
                        : finding.Fix.Description
                },
                artifactChanges = new[]
                {
                    new
                    {
                        artifactLocation = new { uri = finding.Fix.Region.FilePath.Replace('\\', '/') },
                        replacements = new[]
                        {
                            new
                            {
                                deletedRegion = new
                                {
                                    startLine = finding.Fix.Region.Line,
                                    startColumn = finding.Fix.Region.Column,
                                    endLine = finding.Fix.Region.Line,
                                    endColumn = finding.Fix.Region.EndColumn
                                },
                                insertedContent = new { text = finding.Fix.ReplacementText }
                            }
                        }
                    }
                }
            }
        };
    }

    /// <summary>
    /// Converts a SkillGuard severity level to a SARIF level.
    /// </summary>
    /// <param name="severity">The severity level to convert.</param>
    /// <returns>The corresponding SARIF level string.</returns>
    public static string ToSarifLevel(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        _ => "note"
    };
}
