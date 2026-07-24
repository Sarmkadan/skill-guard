using SkillGuard.Core;
using Xunit;

namespace SkillGuard.Tests;

/// <summary>
/// Comprehensive tests for <see cref="SkillFileClassifier"/> that verify classification
/// of skill and instruction files based on documented glob patterns and edge cases.
/// </summary>
public class SkillFileClassifierTests
{
    /// <summary>
    /// Test data matrix mapping file paths to expected <see cref="SkillFileKind"/>.
    /// This table serves as both documentation and test data - new patterns should be added here.
    /// </summary>
    public static TheoryData<string, SkillFileKind> ClassificationTestData => new()
    {
        // ==================================================================================
        // CLAUDE SKILL AND AGENT FILES
        // ==================================================================================
        // .claude/skills/** - skill definitions (most specific first)
        { "/repo/.claude/skills/my-skill/SKILL.md", SkillFileKind.ClaudeSkill },
        { "/repo/.claude/skills/*.md", SkillFileKind.ClaudeSkill },
        { "/repo/.claude/skills/**", SkillFileKind.ClaudeSkill },
        { "/repo/.claude/skills/foo/bar/SKILL.md", SkillFileKind.ClaudeSkill },

        // .claude/agents/** - agent definitions
        { "/repo/.claude/agents/agent-definition.json", SkillFileKind.ClaudeSkill },
        { "/repo/.claude/agents/**", SkillFileKind.ClaudeSkill },

        // .claude/commands/** - command definitions
        { "/repo/.claude/commands/deploy.sh", SkillFileKind.ClaudeSkill },
        { "/repo/.claude/commands/**", SkillFileKind.ClaudeSkill },

        // .clinerules - Cline rules file
        { "/repo/.clinerules", SkillFileKind.ClaudeSkill },

        // .windsurfrules - Windsurf rules file
        { "/repo/.windsurfrules", SkillFileKind.ClaudeSkill },

        // ==================================================================================
        // CURSOR RULES AND CONFIGURATION
        // ==================================================================================
        // .cursor/rules/** - Cursor IDE rule files
        { "/repo/.cursor/rules/security.mdc", SkillFileKind.CursorRule },
        { "/repo/.cursor/rules/**", SkillFileKind.CursorRule },
        { "/repo/.cursor/rules/style.mdc", SkillFileKind.CursorRule },
        { "tools/.cursor/rules/security.mdc", SkillFileKind.CursorRule },

        // .mdc - Cursor markdown rule files (extension alone is sufficient)
        { "/repo/.mdc", SkillFileKind.CursorRule },
        { "/repo/rules.mdc", SkillFileKind.CursorRule },
        { "*.mdc", SkillFileKind.CursorRule },
        { ".mdc", SkillFileKind.CursorRule },
        { "/repo/.cursor/rules/security.MDC", SkillFileKind.CursorRule },

        // ==================================================================================
        // MCP MANIFEST FILES
        // ==================================================================================
        // mcp.json - MCP manifest files at any level
        { "/repo/mcp.json", SkillFileKind.McpManifest },
        { "/mcp.json", SkillFileKind.McpManifest },
        { "mcp.json", SkillFileKind.McpManifest },
        { ".mcp.json", SkillFileKind.McpManifest },
        { "*.mcp.json", SkillFileKind.McpManifest },

        // mcp/ - MCP manifest files in mcp directory
        { "/repo/mcp/server.json", SkillFileKind.McpManifest },
        { "/mcp/*.json", SkillFileKind.McpManifest },
        { "/mcp/**/*.json", SkillFileKind.McpManifest },
        { "mcp/**/*.json", SkillFileKind.McpManifest },
        { "config/mcp.json", SkillFileKind.McpManifest },

        // ==================================================================================
        // ADDITIONAL RULE FILES
        // ==================================================================================
        // .augment-guidelines - Augment guidelines file
        { "/repo/.augment-guidelines", SkillFileKind.GenericMarkdown },
        { "docs/.augment-guidelines", SkillFileKind.GenericMarkdown },

        // ==================================================================================
        // MANIFEST FILES (case-insensitive matching for Windows compatibility)
        // ==================================================================================
        // AGENTS.md / agents.md / Agents.md - Agent manifest files
        { "/repo/AGENTS.md", SkillFileKind.AgentsManifest },
        { "/repo/agents.md", SkillFileKind.AgentsManifest },
        { "/repo/Agents.md", SkillFileKind.AgentsManifest },
        { "AGENTS.md", SkillFileKind.AgentsManifest },
        { "agents.md", SkillFileKind.AgentsManifest },
        { "CLAUDE.md", SkillFileKind.AgentsManifest },
        { "docs/CLAUDE.md", SkillFileKind.AgentsManifest },
        { "README.CLAUDE.md", SkillFileKind.AgentsManifest },

        // CLAUDE.md / claude.md / Claude.md - Claude manifest files (case-insensitive)
        { "/repo/CLAUDE.md", SkillFileKind.AgentsManifest },
        { "/repo/claude.md", SkillFileKind.AgentsManifest },
        { "/repo/Claude.md", SkillFileKind.AgentsManifest },
        { "claude.md", SkillFileKind.AgentsManifest },
        { "Claude.MD", SkillFileKind.AgentsManifest },

        // GEMINI.md / gemini.md / Gemini.md - Gemini configuration files
        { "/repo/GEMINI.md", SkillFileKind.GenericMarkdown },
        { "gemini.md", SkillFileKind.GenericMarkdown },

        // ==================================================================================
        // SHELL SCRIPTS
        // ==================================================================================
        { "/repo/deploy.sh", SkillFileKind.ShellScript },
        { "/repo/script.bash", SkillFileKind.ShellScript },
        { "/repo/setup.zsh", SkillFileKind.ShellScript },
        { "/repo/run.ps1", SkillFileKind.ShellScript },
        { "*.sh", SkillFileKind.ShellScript },
        { "*.bash", SkillFileKind.ShellScript },
        { "*.zsh", SkillFileKind.ShellScript },
        { "*.ps1", SkillFileKind.ShellScript },
        { "/repo/scripts/setup.sh", SkillFileKind.ShellScript },
        { "src/.claude/skills/skill.md", SkillFileKind.ClaudeSkill },

        // ==================================================================================
        // GENERIC MARKDOWN FILES
        // ==================================================================================
        { "/repo/README.md", SkillFileKind.GenericMarkdown },
        { "/docs/README.md", SkillFileKind.GenericMarkdown },
        { "path/to/file.md", SkillFileKind.GenericMarkdown },
        { "*.md", SkillFileKind.GenericMarkdown },
        { "/repo/document.markdown", SkillFileKind.GenericMarkdown },
        { "*.markdown", SkillFileKind.GenericMarkdown },
        { "/repo/GEMINI.md", SkillFileKind.GenericMarkdown },
        { "/repo/gemini.md", SkillFileKind.GenericMarkdown },

        // ==================================================================================
        // EDGE CASES AND "OTHER" FILES
        // ==================================================================================
        // Files that should NOT be scanned (classified as Other)
        { "/repo/package.json", SkillFileKind.Other },
        { "/repo/README.txt", SkillFileKind.Other },
        { "/repo/config.xml", SkillFileKind.Other },
        { "/repo/src/Program.cs", SkillFileKind.Other },
        { "*.jpg", SkillFileKind.Other },
        { "*.png", SkillFileKind.Other },
    };

    /// <summary>
    /// Test data for IsScannable method.
    /// </summary>
    public static TheoryData<string, bool> IsScannableTestData => new()
    {
        // Scannable files
        { "/repo/.claude/skills/skill.md", true },
        { "/AGENTS.md", true },
        { "/CLAUDE.md", true },
        { "/GEMINI.md", true },
        { "/deploy.sh", true },
        { "/README.md", true },
        { "/.mdc", true },
        { "/mcp.json", true },

        // Non-scannable files
        { "/package.json", false },
        { "/README.txt", false },
        { "/config.xml", false },
        { "/src/Program.cs", false },
    };

    /// <summary>
    /// Tests basic path-to-kind mapping for common cases.
    /// </summary>
    [Theory]
    [InlineData("/repo/.claude/skills/x/SKILL.md", SkillFileKind.ClaudeSkill)]
    [InlineData("/repo/.claude/agents/reviewer.md", SkillFileKind.ClaudeSkill)]
    [InlineData("/repo/AGENTS.md", SkillFileKind.AgentsManifest)]
    [InlineData("/repo/CLAUDE.md", SkillFileKind.AgentsManifest)]
    [InlineData("/repo/.cursor/rules/style.mdc", SkillFileKind.CursorRule)]
    [InlineData("/repo/.mcp.json", SkillFileKind.McpManifest)]
    [InlineData("/repo/scripts/setup.sh", SkillFileKind.ShellScript)]
    [InlineData("/repo/README.md", SkillFileKind.GenericMarkdown)]
    [InlineData("/repo/Program.cs", SkillFileKind.Other)]
    public void Classify_MapsPathsToKinds(string path, SkillFileKind expected)
    {
        Assert.Equal(expected, SkillFileClassifier.Classify(path));
    }

    /// <summary>
    /// Tests that all file paths are correctly classified according to the classification matrix.
    /// This is the primary table-driven test that validates the entire classification system.
    /// </summary>
    [Theory]
    [MemberData(nameof(ClassificationTestData))]
    public void Classify_ReturnsExpectedKind(string filePath, SkillFileKind expectedKind)
    {
        // Act
        var actualKind = SkillFileClassifier.Classify(filePath);

        // Assert
        Assert.Equal(expectedKind, actualKind);
    }

    /// <summary>
    /// Tests that IsScannable correctly identifies files that should be scanned.
    /// </summary>
    [Theory]
    [MemberData(nameof(IsScannableTestData))]
    public void IsScannable_ReturnsCorrectValue(string filePath, bool expectedScannable)
    {
        // Act
        var isScannable = SkillFileClassifier.IsScannable(filePath);

        // Assert
        Assert.Equal(expectedScannable, isScannable);
    }

    /// <summary>
    /// Tests Windows path separator compatibility (backslashes).
    /// </summary>
    [Fact]
    public void Classify_HandlesWindowsSeparators()
    {
        Assert.Equal(SkillFileKind.ClaudeSkill, SkillFileClassifier.Classify(@"C:\repo\.claude\skills\x\SKILL.md"));
    }

    /// <summary>
    /// Tests that IsScannable excludes files with Other kind.
    /// </summary>
    [Fact]
    public void IsScannable_ExcludesOtherKind()
    {
        Assert.True(SkillFileClassifier.IsScannable("/repo/AGENTS.md"));
        Assert.False(SkillFileClassifier.IsScannable("/repo/app.py"));
    }

    /// <summary>
    /// Tests Windows compatibility (case-insensitive file system).
    /// </summary>
    [Theory]
    [InlineData("CLAUDE.md", SkillFileKind.AgentsManifest)]
    [InlineData("claude.md", SkillFileKind.AgentsManifest)]
    [InlineData("Claude.MD", SkillFileKind.AgentsManifest)]
    [InlineData("AGENTS.MD", SkillFileKind.AgentsManifest)]
    [InlineData("agents.md", SkillFileKind.AgentsManifest)]
    [InlineData(".CURSOR/RULES/security.mdc", SkillFileKind.CursorRule)]
    [InlineData(".cursor/rules/security.MDC", SkillFileKind.CursorRule)]
    public void Classify_HandlesWindowsCaseInsensitivePaths(string filePath, SkillFileKind expectedKind)
    {
        // Act
        var actualKind = SkillFileClassifier.Classify(filePath);

        // Assert
        Assert.Equal(expectedKind, actualKind);
    }

    /// <summary>
    /// Tests nested path variants (e.g., docs/CLAUDE.md).
    /// </summary>
    [Theory]
    [InlineData("docs/CLAUDE.md", SkillFileKind.AgentsManifest)]
    [InlineData("src/.claude/skills/skill.md", SkillFileKind.ClaudeSkill)]
    [InlineData("tools/.cursor/rules/security.mdc", SkillFileKind.CursorRule)]
    [InlineData("config/mcp.json", SkillFileKind.McpManifest)]
    [InlineData("docs/.augment-guidelines", SkillFileKind.GenericMarkdown)]
    public void Classify_HandlesNestedPaths(string filePath, SkillFileKind expectedKind)
    {
        // Act
        var actualKind = SkillFileClassifier.Classify(filePath);

        // Assert
        Assert.Equal(expectedKind, actualKind);
    }

    /// <summary>
    /// Tests that the classifier correctly handles absolute paths.
    /// </summary>
    [Theory]
    [InlineData("/.claude/skills/skill.md", SkillFileKind.ClaudeSkill)]
    [InlineData("/AGENTS.md", SkillFileKind.AgentsManifest)]
    [InlineData("/mcp.json", SkillFileKind.McpManifest)]
    [InlineData("/home/user/project/README.md", SkillFileKind.GenericMarkdown)]
    public void Classify_HandlesAbsolutePaths(string filePath, SkillFileKind expectedKind)
    {
        // Act
        var actualKind = SkillFileClassifier.Classify(filePath);

        // Assert
        Assert.Equal(expectedKind, actualKind);
    }

    /// <summary>
    /// Tests that the classifier correctly handles relative paths with parent directory references.
    /// </summary>
    [Theory]
    [InlineData("../.claude/skills/skill.md", SkillFileKind.ClaudeSkill)]
    [InlineData("../../AGENTS.md", SkillFileKind.AgentsManifest)]
    [InlineData("./.mdc", SkillFileKind.CursorRule)]
    public void Classify_HandlesRelativePathsWithParentReferences(string filePath, SkillFileKind expectedKind)
    {
        // Act
        var actualKind = SkillFileClassifier.Classify(filePath);

        // Assert
        Assert.Equal(expectedKind, actualKind);
    }

    /// <summary>
    /// Tests edge cases and null/empty input validation.
    /// </summary>
    [Fact]
    public void Classify_ThrowsOnInvalidInput()
    {
        // Null input
        Assert.Throws<ArgumentNullException>(() => SkillFileClassifier.Classify(null!));

        // Empty string
        Assert.Throws<ArgumentException>(() => SkillFileClassifier.Classify(string.Empty));

        // Whitespace only
        Assert.Throws<ArgumentException>(() => SkillFileClassifier.Classify(" "));
    }

    /// <summary>
    /// Tests that IsScannable throws on invalid input.
    /// </summary>
    [Fact]
    public void IsScannable_ThrowsOnInvalidInput()
    {
        // Null input
        Assert.Throws<ArgumentNullException>(() => SkillFileClassifier.IsScannable(null!));

        // Empty string
        Assert.Throws<ArgumentException>(() => SkillFileClassifier.IsScannable(string.Empty));

        // Whitespace only
        Assert.Throws<ArgumentException>(() => SkillFileClassifier.IsScannable(" "));
    }
}