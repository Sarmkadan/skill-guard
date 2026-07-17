using System.Text.Json;

namespace SkillGuard.Core;

public sealed class SarifReporter(string toolVersion = "0.1.0") : IReporter
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public void Write(ScanReport report, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(output);
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
            }
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
                            version = toolVersion,
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

    public static string ToSarifLevel(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        _ => "note"
    };
}
