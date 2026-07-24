namespace SkillGuard.Core;

/// <summary>
/// Provides classification of skill and instruction files based on their paths and extensions.
/// Maps file paths to <see cref="SkillFileKind"/> to determine how files should be scanned.
/// </summary>
public static class SkillFileClassifier
{
    /// <summary>
    /// Classification rules mapping file patterns to their corresponding <see cref="SkillFileKind"/>.
    /// Patterns are ordered from most specific to least specific to ensure correct classification.
    /// Supports both relative and absolute paths, case-insensitive matching, and nested file locations.
    /// </summary>
    /// <remarks>
    /// <para><strong>Classification Matrix:</strong></para>
    ///
    /// <para><strong>Claude Skill Files:</strong> Files that define agent skills and commands</para>
    /// <list type="bullet">
    ///   <item><description><c>.claude/skills/*</c> - Skill definitions</description></item>
    ///   <item><description><c>.claude/agents/*</c> - Agent definitions</description></item>
    ///   <item><description><c>.claude/commands/*</c> - Command definitions</description></item>
    ///   <item><description><c>.clinerules</c> - Cline rules file</description></item>
    ///   <item><description><c>.windsurfrules</c> - Windsurf rules file</description></item>
    /// </list>
    ///
    /// <para><strong>Cursor Rule Files:</strong> Files that define Cursor IDE rules</para>
    /// <list type="bullet">
    ///   <item><description><c>.cursor/rules/*</c> - Cursor rule definitions</description></item>
    ///   <item><description><c>.mdc</c> - Cursor markdown rule files</description></item>
    /// </list>
    ///
    /// <para><strong>MCP Manifest Files:</strong> Files that define MCP server configurations</para>
    /// <list type="bullet">
    ///   <item><description><c>mcp.json</c> - MCP manifest at any level</description></item>
    ///   <item><description><c>.mcp.json</c> - Hidden MCP manifest</description></item>
    ///   <item><description><c>mcp/*.json</c> - MCP manifests in mcp directory</description></item>
    /// </list>
    ///
    /// <para><strong>Agent Manifest Files:</strong> Files that define agent instructions and configurations</para>
    /// <list type="bullet">
    ///   <item><description><c>AGENTS.md</c> / <c>agents.md</c> / <c>Claude.md</c> / <c>claude.md</c> - Case-insensitive manifest files</description></item>
    ///   <item><description><c>GEMINI.md</c> / <c>gemini.md</c> - Gemini configuration files</description></item>
    /// </list>
    ///
    /// <para><strong>Rule and Guideline Files:</strong></para>
    /// <list type="bullet">
    ///   <item><description><c>.augment-guidelines</c> - Augment guidelines file</description></item>
    /// </list>
    ///
    /// <para><strong>Shell Scripts:</strong> Executable shell scripts</para>
    /// <list type="bullet">
    ///   <item><description><c>*.sh</c> - Bourne shell scripts</description></item>
    ///   <item><description><c>*.bash</c> - Bash shell scripts</description></item>
    ///   <item><description><c>*.zsh</c> - Z shell scripts</description></item>
    ///   <item><description><c>*.ps1</c> - PowerShell scripts</description></item>
    /// </list>
    ///
    /// <para><strong>Generic Files:</strong></para>
    /// <list type="bullet">
    ///   <item><description><c>*.md</c> / <c>*.markdown</c> - Markdown documentation</description></item>
    ///   <item><description><c>*</c> - All other files (classified as <see cref="SkillFileKind.Other"/>)</description></item>
    /// </list>
    /// </remarks>
    private static readonly (string Pattern, SkillFileKind Kind)[] _classificationRules =
    {
        // ==================================================================================
        // CLAUDE SKILL AND AGENT FILES
        // ==================================================================================
        // .claude/skills/** - skill definitions (most specific first)
        (".claude/skills/*", SkillFileKind.ClaudeSkill),
        ("/.claude/skills/*", SkillFileKind.ClaudeSkill),
        (".claude/skills/**", SkillFileKind.ClaudeSkill),
        ("/.claude/skills/**", SkillFileKind.ClaudeSkill),

        // .claude/agents/** - agent definitions
        (".claude/agents/*", SkillFileKind.ClaudeSkill),
        ("/.claude/agents/*", SkillFileKind.ClaudeSkill),
        (".claude/agents/**", SkillFileKind.ClaudeSkill),
        ("/.claude/agents/**", SkillFileKind.ClaudeSkill),

        // .claude/commands/** - command definitions
        (".claude/commands/*", SkillFileKind.ClaudeSkill),
        ("/.claude/commands/*", SkillFileKind.ClaudeSkill),
        (".claude/commands/**", SkillFileKind.ClaudeSkill),
        ("/.claude/commands/**", SkillFileKind.ClaudeSkill),

        // .clinerules - Cline rules file
        (".clinerules", SkillFileKind.ClaudeSkill),
        ("/.clinerules", SkillFileKind.ClaudeSkill),

        // .windsurfrules - Windsurf rules file
        (".windsurfrules", SkillFileKind.ClaudeSkill),
        ("/.windsurfrules", SkillFileKind.ClaudeSkill),

        // ==================================================================================
        // CURSOR RULES AND CONFIGURATION
        // ==================================================================================
        // .cursor/rules/** - Cursor IDE rule files
        (".cursor/rules/*", SkillFileKind.CursorRule),
        ("/.cursor/rules/*", SkillFileKind.CursorRule),
        (".cursor/rules/**", SkillFileKind.CursorRule),
        ("/.cursor/rules/**", SkillFileKind.CursorRule),

        // .mdc - Cursor markdown rule files
        (".mdc", SkillFileKind.CursorRule),
        ("/.mdc", SkillFileKind.CursorRule),
        ("*.mdc", SkillFileKind.CursorRule),

        // ==================================================================================
        // MCP MANIFEST FILES (case-insensitive, supports nested locations)
        // ==================================================================================
        // mcp.json - MCP manifest files at any level
        ("mcp.json", SkillFileKind.McpManifest),
        ("/mcp.json", SkillFileKind.McpManifest),
        (".mcp.json", SkillFileKind.McpManifest),
        ("/.mcp.json", SkillFileKind.McpManifest),
        ("*.mcp.json", SkillFileKind.McpManifest),

        // mcp/ - MCP manifest files in mcp directory
        ("mcp/*.json", SkillFileKind.McpManifest),
        ("/mcp/*.json", SkillFileKind.McpManifest),
        ("mcp/**/*.json", SkillFileKind.McpManifest),
        ("/mcp/**/*.json", SkillFileKind.McpManifest),

        // ==================================================================================
        // ADDITIONAL RULE FILES
        // ==================================================================================
        // .augment-guidelines - Augment guidelines file
        (".augment-guidelines", SkillFileKind.GenericMarkdown),
        ("/.augment-guidelines", SkillFileKind.GenericMarkdown),

        // ==================================================================================
        // MANIFEST FILES (case-insensitive matching for Windows compatibility)
        // ==================================================================================
        // AGENTS.md / agents.md / Agents.md - Agent manifest files
        ("AGENTS.md", SkillFileKind.AgentsManifest),
        ("/AGENTS.md", SkillFileKind.AgentsManifest),
        ("agents.md", SkillFileKind.AgentsManifest),
        ("/agents.md", SkillFileKind.AgentsManifest),
        ("*.agents.md", SkillFileKind.AgentsManifest),

        // CLAUDE.md / claude.md / Claude.md - Claude manifest files (case-insensitive)
        ("CLAUDE.md", SkillFileKind.AgentsManifest),
        ("/CLAUDE.md", SkillFileKind.AgentsManifest),
        ("claude.md", SkillFileKind.AgentsManifest),
        ("/claude.md", SkillFileKind.AgentsManifest),
        ("*.claude.md", SkillFileKind.AgentsManifest),

        // GEMINI.md / gemini.md / Gemini.md - Gemini configuration files
        ("GEMINI.md", SkillFileKind.GenericMarkdown),
        ("/GEMINI.md", SkillFileKind.GenericMarkdown),
        ("gemini.md", SkillFileKind.GenericMarkdown),
        ("/gemini.md", SkillFileKind.GenericMarkdown),
        ("*.gemini.md", SkillFileKind.GenericMarkdown),

        // ==================================================================================
        // SHELL SCRIPTS
        // ==================================================================================
        ("*.sh", SkillFileKind.ShellScript),
        ("*.bash", SkillFileKind.ShellScript),
        ("*.zsh", SkillFileKind.ShellScript),
        ("*.ps1", SkillFileKind.ShellScript),

        // ==================================================================================
        // GENERIC FILES (must come last - least specific patterns)
        // ==================================================================================
        // Generic markdown files
        ("*.md", SkillFileKind.GenericMarkdown),
        ("*.markdown", SkillFileKind.GenericMarkdown),

        // All other files
        ("*", SkillFileKind.Other)
    };

    /// <summary>
    /// Classifies the specified file path into a <see cref="SkillFileKind"/>.
    /// </summary>
    /// <param name="filePath">The file path to classify (supports both relative and absolute paths).</param>
    /// <returns>The <see cref="SkillFileKind"/> corresponding to the file path.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filePath"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="filePath"/> is empty or consists only of whitespace.</exception>
    public static SkillFileKind Classify(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        var normalized = filePath.Replace('\\', '/');

        // Check path patterns first (most specific to least specific)
        foreach (var (pattern, kind) in _classificationRules)
        {
            if (PatternMatches(normalized, pattern))
            {
                return kind;
            }
        }

        // Fallback to simple extension-based classification for files not matching any pattern
        var fileName = Path.GetFileName(normalized);
        var extension = Path.GetExtension(fileName);
        var lowerFileName = fileName.ToLowerInvariant();
        var lowerExtension = extension.ToLowerInvariant();

        // Check for exact matches (case-insensitive for manifest files)
        if (lowerFileName is "agents.md" or "claude.md")
        {
            return SkillFileKind.AgentsManifest;
        }

        if (lowerFileName is ".mcp.json" or "mcp.json")
        {
            return SkillFileKind.McpManifest;
        }

        if (lowerExtension is ".md" or ".markdown")
        {
            return SkillFileKind.GenericMarkdown;
        }

        if (lowerExtension is ".sh" or ".bash" or ".zsh" or ".ps1")
        {
            return SkillFileKind.ShellScript;
        }

        if (lowerFileName is ".mdc")
        {
            return SkillFileKind.CursorRule;
        }

        return SkillFileKind.Other;
    }

    /// <summary>
    /// Determines whether the specified file path matches the given glob pattern.
    /// </summary>
    /// <param name="path">The file path to match against the pattern.</param>
    /// <param name="pattern">The glob pattern to match (e.g., ".claude/skills/*").</param>
    /// <returns><see langword="true"/> if the path matches the pattern; otherwise, <see langword="false"/>.</returns>
    /// <remarks>
    /// This method converts glob patterns (with * wildcards) to regular expressions.
    /// The pattern matching is case-insensitive to support Windows file systems.
    /// </remarks>
    private static bool PatternMatches(string path, string pattern)
    {
        // Convert glob pattern to regex - pattern can match anywhere in the path
        // Escape dots and slashes properly for regex
        var regexPattern = pattern
            .Replace(".", "\\.")  // Escape literal dots in patterns like ".mdc"
            .Replace("*", ".*")  // Wildcard becomes regex wildcard
            .Replace("/", "/");   // Forward slashes don't need escaping

        var regex = new System.Text.RegularExpressions.Regex(
            regexPattern,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
        );

        return regex.IsMatch(path);
    }

    /// <summary>
    /// Determines whether the specified file path represents a scannable file.
    /// A file is scannable if its <see cref="SkillFileKind"/> is not <see cref="SkillFileKind.Other"/>.
    /// </summary>
    /// <param name="filePath">The file path to check.</param>
    /// <returns><see langword="true"/> if the file should be scanned; otherwise, <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="filePath"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="filePath"/> is empty or consists only of whitespace.</exception>
    public static bool IsScannable(string filePath) => Classify(filePath) != SkillFileKind.Other;
}