using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class NetworkEgressRule : IScanRule
{
    public string Id => "SG005";
    public string Name => "NetworkEgress";
    public string Description => "Flags outbound network calls to hosts outside the allowlist";
    public Severity DefaultSeverity => Severity.Medium;
    public FindingCategory Category => FindingCategory.NetworkEgress;

    public static readonly IReadOnlySet<string> DefaultAllowedHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "github.com", "raw.githubusercontent.com", "api.github.com", "objects.githubusercontent.com",
        "gitlab.com", "nuget.org", "api.nuget.org", "www.nuget.org",
        "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io",
        "dot.net", "dotnet.microsoft.com", "aka.ms", "localhost", "127.0.0.1"
    };

    private static readonly Regex UrlPattern = new(@"https?://([A-Za-z0-9.-]+)(:\d+)?[^\s""'`\)\]>]*", RegexOptions.Compiled);
    private static readonly Regex RawIpPattern = new(@"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", RegexOptions.Compiled);
    private static readonly Regex NetClientPattern = new(@"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc)\b", RegexOptions.Compiled);

    public IReadOnlySet<string> AllowedHosts { get; }

    public NetworkEgressRule(IEnumerable<string>? additionalAllowedHosts = null)
    {
        var hosts = new HashSet<string>(DefaultAllowedHosts, StringComparer.OrdinalIgnoreCase);
        if (additionalAllowedHosts is not null) hosts.UnionWith(additionalAllowedHosts);
        AllowedHosts = hosts;
    }

    public IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return ScanCore(target);
    }

    private IEnumerable<Finding> ScanCore(ScanTarget target)
    {
        for (var i = 0; i < target.Lines.Length; i++)
        {
            var line = target.Lines[i];
            foreach (Match match in UrlPattern.Matches(line))
            {
                var host = match.Groups[1].Value;
                if (AllowedHosts.Contains(host)) continue;
                var isRawIp = RawIpPattern.IsMatch(match.Value);
                var invokesClient = NetClientPattern.IsMatch(line);
                var severity = (isRawIp, invokesClient) switch
                {
                    (true, _) => Severity.High,
                    (false, true) => Severity.Medium,
                    _ => Severity.Low
                };
                var reason = isRawIp
                    ? $"Network egress to raw IP address {host}"
                    : invokesClient
                        ? $"Network client invocation targeting unexpected host {host}"
                        : $"Reference to unexpected external host {host}";
                yield return new Finding(Id, Name, severity, Category, reason,
                    SourceLocation.At(target.FilePath, i + 1, match.Index + 1, match.Length),
                    line.Trim().Length > 200 ? line.Trim()[..200] : line.Trim())
                { Remediation = "Restrict skill network access to reviewed, allowlisted hosts" };
            }
        }
    }
}
