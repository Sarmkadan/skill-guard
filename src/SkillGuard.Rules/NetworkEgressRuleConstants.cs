using System.Collections.Generic;

namespace SkillGuard.Rules;

internal static class NetworkEgressRuleConstants
{
    public const string Id = "SG005";
    public const string Name = "NetworkEgress";
    public const string Description = "Flags outbound network calls to hosts outside the allowlist";
    public const string RemediationMessage = "Restrict skill network access to reviewed, allowlisted hosts";

    public const int MaxReasonLength = 200;

    public const string UrlPattern = @"https?://([A-Za-z0-9.-]+)(:\d+)?[^\s""'`\)\]>]*";
    public const string RawIpPattern = @"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})";
    public const string NetClientPattern = @"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc)\b";

    public const string ReasonRawIp = "Network egress to raw IP address {0}";
    public const string ReasonClientInvocation = "Network client invocation targeting unexpected host {0}";
    public const string ReasonReference = "Reference to unexpected external host {0}";

    public static readonly string[] DefaultAllowedHosts = new[]
    {
        "github.com", "raw.githubusercontent.com", "api.github.com", "objects.githubusercontent.com",
        "gitlab.com", "nuget.org", "api.nuget.org", "www.nuget.org",
        "registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "crates.io",
        "dot.net", "dotnet.microsoft.com", "aka.ms", "localhost", "127.0.0.1"
    };
}
