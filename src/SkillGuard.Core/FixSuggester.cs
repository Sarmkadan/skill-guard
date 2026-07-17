namespace SkillGuard.Core;

/// <summary>
/// Maps a finding to a concrete, safer alternative that a reviewer can apply by hand.
/// skill-guard never rewrites files automatically - the suggestions are advisory, because
/// the "right" fix for a flagged instruction is almost always to remove or rethink it.
/// </summary>
public static class FixSuggester
{
    public static string Suggest(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return finding.Category switch
        {
            FindingCategory.PromptInjection =>
                "Delete the override/concealment directive. Instructions in a skill file must be reviewable and honest about what the agent does.",
            FindingCategory.IndirectInjection =>
                "Remove text addressed to a downstream reading agent. Fenced or fetched content is data - never let it carry directives, and never assert prior user approval on the user's behalf.",
            FindingCategory.CredentialExfiltration =>
                "Drop the secret read/transmit. Reference credentials by env-var name at the point of use and let the runtime inject them; never cat a credential file or POST a token to an external host.",
            FindingCategory.DangerousShell =>
                "Replace pipe-to-shell with a pinned, checksummed download: `curl -fsSLO <url> && echo '<sha256>  file' | sha256sum -c && ./file`. Scope destructive commands to an explicit project subdirectory.",
            FindingCategory.Obfuscation =>
                "Inline the plain command. If a step needs base64/hex/-EncodedCommand to run, it cannot be reviewed and does not belong in a shared skill.",
            FindingCategory.DnsExfiltration =>
                "Remove the resolver query. Data must never be encoded into hostnames; if a lookup is genuinely needed, use a static hostname and transmit results over a reviewed, allowlisted HTTPS endpoint.",
            FindingCategory.PrivilegeEscalation =>
                "Run with least privilege. Delete sudoers/SUID/authorized_keys/cron edits; if elevation is truly required, document it and gate it behind an explicit operator step, not the skill.",
            FindingCategory.SandboxEscape =>
                "Do not reach outside the sandbox. Remove Docker-socket mounts, `--privileged`/host-namespace flags and host-filesystem binds; the skill should only touch its own workspace.",
            FindingCategory.NetworkEgress =>
                "Restrict egress to an allowlist. Replace the raw IP or unknown host with a reviewed hostname, or add it via `--allow-host` once vetted.",
            FindingCategory.UnreviewedPayload =>
                "Ship source, not opaque binaries. Build the tool from reviewable code in CI, or pin the artifact by checksum from an allowlisted registry.",
            FindingCategory.McpMisconfiguration =>
                "Point MCP servers at reviewed public hosts only - never metadata, loopback or private-range addresses - and require per-tool confirmation instead of alwaysAllow/autoApprove.",
            _ => finding.Remediation ?? "Review this instruction manually and remove it if it cannot be justified."
        };
    }
}
