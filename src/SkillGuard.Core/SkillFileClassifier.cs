namespace SkillGuard.Core;

public static class SkillFileClassifier
{
    public static SkillFileKind Classify(string filePath)
    {
        var normalized = filePath.Replace('\\', '/');
        var fileName = Path.GetFileName(normalized);
        var ext = Path.GetExtension(fileName).ToLowerInvariant();
        return normalized switch
        {
            _ when normalized.Contains("/.claude/skills/") || normalized.Contains("/.claude/agents/") => SkillFileKind.ClaudeSkill,
            _ when fileName is "AGENTS.md" or "CLAUDE.md" => SkillFileKind.AgentsManifest,
            _ when normalized.Contains("/.cursor/rules/") || ext == ".mdc" => SkillFileKind.CursorRule,
            _ when fileName is "mcp.json" or ".mcp.json" || fileName.EndsWith(".mcp.json", StringComparison.OrdinalIgnoreCase) => SkillFileKind.McpManifest,
            _ when ext is ".sh" or ".bash" or ".zsh" or ".ps1" => SkillFileKind.ShellScript,
            _ when ext is ".md" or ".markdown" => SkillFileKind.GenericMarkdown,
            _ => SkillFileKind.Other
        };
    }

    public static bool IsScannable(string filePath) => Classify(filePath) != SkillFileKind.Other;
}
