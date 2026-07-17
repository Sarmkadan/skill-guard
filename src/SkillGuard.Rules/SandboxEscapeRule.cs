using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class SandboxEscapeRule : RegexScanRule
{
    public override string Id => "SG010";
    public override string Name => "SandboxEscape";
    public override string Description => "Detects container and sandbox escape techniques";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.SandboxEscape;
    public override string? Remediation => "A skill should never reach outside its sandbox; remove Docker-socket, host-namespace and host-filesystem access";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"(-v\s+|--volume[= ])/var/run/docker\.sock|curl\s+[^\n]*--unix-socket\s+/var/run/docker\.sock", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Mounts or talks to the Docker socket, granting host control", Severity.Critical),
        new(new Regex(@"\bdocker\s+run\b[^\n]*(--privileged|--pid[= ]host|--net[= ]host|--cap-add[= ]SYS_ADMIN)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Launches a container with host-level privileges", Severity.Critical),
        new(new Regex(@"\bnsenter\b[^\n]*(--target\s+1|-t\s+1)|\bnsenter\s+-a\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Enters the host PID namespace to break out of the container", Severity.Critical),
        new(new Regex(@"\bmount\b[^\n]*(/dev/sd|/host|--bind\s+/)|\bchroot\s+/host", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Mounts the host filesystem into the sandbox"),
        new(new Regex(@"/proc/(1|self)/root/|echo[^\n]*>\s*/proc/sys/kernel/core_pattern|release_agent", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Abuses /proc or cgroup release_agent for a known escape primitive", Severity.Critical),
        new(new Regex(@"(-v\s+|--volume[= ])/:/|--volume[= ]/host", RegexOptions.Compiled),
            "Bind-mounts the host root into a container"),
    ];
}
