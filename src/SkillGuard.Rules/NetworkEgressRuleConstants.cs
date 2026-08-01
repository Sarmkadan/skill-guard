using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace SkillGuard.Rules
{
    internal static class NetworkEgressRuleConstants
    {
        public const string DefaultAllowedHosts = "github.com, raw.githubusercontent.com, api.github.com, objects.githubusercontent.com, gitlab.com, nuget.org, api.nuget.org, www.nuget.org, registry.npmjs.org, pypi.org, files.pythonhosted.org, crates.io, dot.net, dotnet.microsoft.com, aka.ms, localhost, 127.0.0.1";
        public const string UrlPattern = "https?://([A-Za-z0-9.-]+)(:\d+)?[^\\s\"\\]\\]*";
        public const string RawIpPattern = "https?://(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})";
        public const string NetClientPattern = "\\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|nc)\\b";
    }
}
