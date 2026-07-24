using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class DangerousShellRule : RegexScanRule, ISuggestsFix
{
    public override string Id => "SG003";
    public override string Name => "DangerousShell";
    public override string Description => "Detects destructive or remote-execution shell invocations";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.DangerousShell;
    public override string? Remediation => "Replace remote pipe-to-shell and destructive commands with pinned, reviewable steps";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =

    [
        new(new Regex(@"(curl|wget)\s+[^|;&]*\|\s*(sudo\s+)?(ba)?sh\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Pipes a remote download directly into a shell", Severity.Critical),
        new(new Regex(@"(curl|wget)\s+[^|;&]*\|\s*(sudo\s+)?(python3?|node|perl|ruby)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Pipes a remote download directly into an interpreter", Severity.Critical),
        new(new Regex(@"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+(/|~|\$HOME|\*)", RegexOptions.Compiled),
            "Recursive forced delete against a broad path", Severity.Critical),
        new(new Regex(@"\bchmod\s+(-R\s+)?(777|a\+rwx)\b", RegexOptions.Compiled),
            "World-writable permission change", Severity.Medium),
        new(new Regex(@"\bmkfs\.|\bdd\s+if=.*of=/dev/", RegexOptions.Compiled),
            "Direct disk-destructive command"),
        new(new Regex(@">\s*/dev/sd[a-z]\b", RegexOptions.Compiled),
            "Writes directly to a block device"),
        new(new Regex(@"\b(nc|ncat|netcat)\s+(-[a-zA-Z]*e|\S+\s+\d+\s+-e)\b", RegexOptions.Compiled),
            "Netcat with command execution (reverse shell)", Severity.Critical),
        new(new Regex(@"\bsudo\s+(rm|chown|chmod|mv|cp)\s+[^\n]*(/etc/|/usr/|/boot/)", RegexOptions.Compiled),
            "Privileged modification of system directories", Severity.Medium)
    ];

    public override IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ScanCore(target);
    }

    /// <summary>
    /// Provides automatic fix suggestions for dangerous shell findings.
    /// Implements <see cref="ISuggestsFix"/> to enable rule-specific fix generation.
    /// </summary>
    /// <param name="finding">The finding to provide a fix for</param>
    /// <returns>A Fix object if a fix can be suggested, null otherwise</returns>
    public Fix? SuggestFix(Finding finding)
    {
        // Only provide fixes for findings from this rule
        if (finding.RuleId != Id)
        {
            return null;
        }

        // Match fix based on finding message
        return finding.Message switch
        {
            "Pipes a remote download directly into a shell" =>
                new Fix(
                    "# Download and verify before execution\n" +
                    "curl -fsSLO https://example.com/tool.tar.gz\n" +
                    "echo 'expected-sha256 tool.tar.gz' | sha256sum -c -\n" +
                    "tar -xzf tool.tar.gz\n" +
                    "./tool --args",
                    finding.Location
                )
                {
                    Description = "Replace shell pipe with pinned download and verification"
                },

            "Pipes a remote download directly into an interpreter" =>
                new Fix(
                    "# Download and verify before execution\n" +
                    "curl -fsSLO https://example.com/script.py\n" +
                    "echo 'expected-sha256 script.py' | sha256sum -c -\n" +
                    "python3 script.py --args",
                    finding.Location
                )
                {
                    Description = "Replace interpreter pipe with pinned download and verification"
                },

            "Recursive forced delete against a broad path" =>
                new Fix(
                    "# Delete only specific files\n" +
                    "rm -f specific-file-to-remove.txt",
                    finding.Location
                )
                {
                    Description = "Replace recursive forced delete with specific file deletion"
                },

            "World-writable permission change" =>
                new Fix(
                    "# Restrict permissions appropriately\n" +
                    "chmod 644 file.txt",
                    finding.Location
                )
                {
                    Description = "Replace world-writable permission change with restrictive permissions"
                },

            "Direct disk-destructive command" =>
                new Fix(
                    "# Use safe file operations\n" +
                    "rm -f specific-file.txt",
                    finding.Location
                )
                {
                    Description = "Replace disk-destructive command with safe file removal"
                },

            "Writes directly to a block device" =>
                new Fix(
                    "# Write to a file instead\n" +
                    "echo 'data' > output.txt",
                    finding.Location
                )
                {
                    Description = "Replace block device write with file write"
                },

            "Netcat with command execution (reverse shell)" =>
                new Fix(
                    "# Use secure communication\n" +
                    "# Consider using HTTPS with proper authentication",
                    finding.Location
                )
                {
                    Description = "Replace netcat reverse shell with secure communication"
                },

            "Privileged modification of system directories" =>
                new Fix(
                    "# Use user-specific directories\n" +
                    "mkdir -p ~/.local/bin\n" +
                    "cp tool ~/.local/bin/",
                    finding.Location
                )
                {
                    Description = "Replace privileged system modification with user-local installation"
                },

            _ => null
        };
    }
}