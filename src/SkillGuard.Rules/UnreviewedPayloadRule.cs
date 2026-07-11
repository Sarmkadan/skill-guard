using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class UnreviewedPayloadRule : IScanRule
{
    public string Id => "SG006";
    public string Name => "UnreviewedPayload";
    public string Description => "Flags skill bundles that download, extract, or invoke opaque binary artifacts";
    public Severity DefaultSeverity => Severity.Medium;
    public FindingCategory Category => FindingCategory.UnreviewedPayload;

    private static readonly Regex BinaryReference = new(@"\b[\w./-]+\.(exe|dll|so|dylib|bin|jar|pyc|wasm)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ArchiveExecution = new(@"(unzip|tar\s+-?x[a-z]*|7z\s+x|Expand-Archive)[^\n]*&&[^\n]*\./", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex RemoteBinaryFetch = new(@"(curl|wget)[^\n]*\.(exe|dll|so|bin|jar)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ScanCore(target);
    }

    private IEnumerable<Finding> ScanCore(ScanTarget target)
    {
        if (target.Kind == SkillFileKind.Other) yield break;
        for (var i = 0; i < target.Lines.Length; i++)
        {
            var line = target.Lines[i];
            var snippet = line.Trim().Length > 200 ? line.Trim()[..200] : line.Trim();
            var remoteFetch = RemoteBinaryFetch.Match(line);
            if (remoteFetch.Success)
            {
                yield return new Finding(Id, Name, Severity.High, Category,
                    "Downloads a binary artifact that cannot be reviewed as text",
                    SourceLocation.At(target.FilePath, i + 1, remoteFetch.Index + 1, remoteFetch.Length), snippet);
                continue;
            }
            var archiveRun = ArchiveExecution.Match(line);
            if (archiveRun.Success)
            {
                yield return new Finding(Id, Name, Severity.High, Category,
                    "Extracts an archive and immediately executes its contents",
                    SourceLocation.At(target.FilePath, i + 1, archiveRun.Index + 1, archiveRun.Length), snippet);
                continue;
            }
            var binary = BinaryReference.Match(line);
            if (binary.Success && target.Kind is SkillFileKind.ClaudeSkill or SkillFileKind.CursorRule or SkillFileKind.McpManifest)
            {
                yield return new Finding(Id, Name, DefaultSeverity, Category,
                    $"Skill file references opaque binary {binary.Value}",
                    SourceLocation.At(target.FilePath, i + 1, binary.Index + 1, binary.Length), snippet);
            }
        }
    }
}
