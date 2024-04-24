using System.Text.RegularExpressions;

namespace SkillGuard.Core;

public sealed record PatternDefinition(Regex Pattern, string Message, Severity? SeverityOverride = null);

public abstract class RegexScanRule : IScanRule
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract string Description { get; }
    public abstract Severity DefaultSeverity { get; }
    public abstract FindingCategory Category { get; }
    public virtual string? Remediation => null;
    protected abstract IReadOnlyList<PatternDefinition> Patterns { get; }
    protected virtual bool AppliesTo(ScanTarget target) => true;

    public IEnumerable<Finding> Scan(ScanTarget target)
    {
        if (!AppliesTo(target)) yield break;
        for (var i = 0; i < target.Lines.Length; i++)
        {
            var line = target.Lines[i];
            foreach (var definition in Patterns)
            {
                foreach (Match match in definition.Pattern.Matches(line))
                {
                    yield return new Finding(
                        Id,
                        Name,
                        definition.SeverityOverride ?? DefaultSeverity,
                        Category,
                        definition.Message,
                        SourceLocation.At(target.FilePath, i + 1, match.Index + 1, match.Length),
                        line.Trim().Length > 200 ? line.Trim()[..200] : line.Trim())
                    { Remediation = Remediation };
                }
            }
        }
    }
}
