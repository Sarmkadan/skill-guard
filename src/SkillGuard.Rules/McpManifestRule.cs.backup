using System.Text.Json;
using System.Text.Json.Nodes;
using SkillGuard.Core;

namespace SkillGuard.Rules;

/// <summary>
/// Detects dangerous configurations in MCP (Model Context Protocol) manifest files (mcp.json).
/// This rule parses the JSON structure and checks for:
/// - Shell commands with npx/uvx/sh -c patterns
/// - Environment variables with credential patterns
/// - Non-HTTPS URLs (SSRF risks)
/// - Malformed JSON
/// Uses System.Text.Json for accurate parsing and source location tracking.
/// </summary>
public sealed class McpManifestRule : IScanRule
{
    public string Id => "SG013";
    public string Name => "McpManifest";
    public string Description => "Detects dangerous configurations in MCP manifest files (mcp.json)";
    public Severity DefaultSeverity => Severity.High;
    public FindingCategory Category => FindingCategory.McpMisconfiguration;
    public string? Remediation =>
        "Review MCP server configurations for security risks:\n" +
        "- Replace shell commands with safe alternatives\n" +
        "- Remove credential-related environment variables\n" +
        "- Use HTTPS endpoints only\n" +
        "- Disable auto-approval features";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private static readonly HashSet<string> ShellCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "sh", "bash", "zsh", "powershell", "cmd", "dash",
        "npx", "uvx", "deno", "bun", "node"
    };

    private static readonly HashSet<string> CredentialPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "TOKEN", "SECRET", "KEY", "PASSWORD", "CREDENTIAL",
        "ACCESS", "API_KEY", "CLIENT_ID", "CLIENT_SECRET"
    };

    public IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);

        // Only apply to MCP manifests
        if (target.Kind != SkillFileKind.McpManifest)
        {
            yield break;
        }

        // Try to parse as JSON
        using var doc = TryParseJson(target);
        if (doc is null)
        {
            yield return new Finding(
                Id,
                Name,
                Severity.Critical,
                Category,
                "Malformed JSON in MCP manifest file",
                SourceLocation.At(target.FilePath, 1, 1, 1),
                target.Content.Length > 200 ? target.Content[..200] : target.Content
            );
            yield break;
        }

        // Check for mcpServers section
        if (!doc.RootElement.TryGetProperty("mcpServers", out var mcpServers))
        {
            yield break; // Not an MCP manifest or empty
        }

        // Process each server definition
        foreach (var finding in CheckServerDefinitions(mcpServers, target.FilePath))
        {
            yield return finding;
        }
    }

    private JsonDocument? TryParseJson(ScanTarget target)
    {
        try
        {
            // Use JsonDocument to preserve line/column information
            using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(target.Content));
            return JsonDocument.Parse(stream);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private IEnumerable<Finding> CheckServerDefinitions(JsonElement mcpServers, string filePath)
    {
        foreach (var server in mcpServers.EnumerateObject())
        {
            var serverName = server.Name;
            var serverValue = server.Value;

            // Check for auto-approval flags
            foreach (var finding in CheckAutoApproval(serverValue, filePath, serverName))
            {
                yield return finding;
            }

            // Check command and args for shell injection
            foreach (var finding in CheckShellCommands(serverValue, filePath, serverName))
            {
                yield return finding;
            }

            // Check environment variables for credentials
            foreach (var finding in CheckEnvironmentVariables(serverValue, filePath, serverName))
            {
                yield return finding;
            }

            // Check URLs for SSRF and non-HTTPS
            foreach (var finding in CheckUrls(serverValue, filePath, serverName))
            {
                yield return finding;
            }
        }
    }

    private IEnumerable<Finding> CheckAutoApproval(JsonElement serverValue, string filePath, string serverName)
    {
        // Check for dangerous auto-approval flags
        if (serverValue.TryGetProperty("autoApprove", out var autoApprove) && autoApprove.ValueKind == JsonValueKind.True)
        {
            var location = GetPropertyLocation(serverValue, "autoApprove", filePath);
            yield return new Finding(
                Id,
                Name,
                Severity.High,
                Category,
                $"MCP server '{serverName}' has autoApprove set to true, disabling per-tool confirmation",
                location,
                GetSnippet(serverValue, "autoApprove")
            );
        }

        if (serverValue.TryGetProperty("autoRun", out var autoRun) && autoRun.ValueKind == JsonValueKind.True)
        {
            var location = GetPropertyLocation(serverValue, "autoRun", filePath);
            yield return new Finding(
                Id,
                Name,
                Severity.High,
                Category,
                $"MCP server '{serverName}' has autoRun set to true, automatically executing on startup",
                location,
                GetSnippet(serverValue, "autoRun")
            );
        }

        if (serverValue.TryGetProperty("alwaysAllow", out var alwaysAllow) && alwaysAllow.ValueKind == JsonValueKind.True)
        {
            var location = GetPropertyLocation(serverValue, "alwaysAllow", filePath);
            yield return new Finding(
                Id,
                Name,
                Severity.High,
                Category,
                $"MCP server '{serverName}' has alwaysAllow set to true, bypassing all permissions",
                location,
                GetSnippet(serverValue, "alwaysAllow")
            );
        }
    }

    private IEnumerable<Finding> CheckShellCommands(JsonElement serverValue, string filePath, string serverName)
    {
        // Check for command property
        if (serverValue.TryGetProperty("command", out var command) && command.ValueKind == JsonValueKind.String)
        {
            var commandStr = command.GetString() ?? string.Empty;
            if (ShellCommands.Contains(commandStr))
            {
                var location = GetPropertyLocation(serverValue, "command", filePath);
                yield return new Finding(
                    Id,
                    Name,
                    Severity.Critical,
                    Category,
                    $"MCP server '{serverName}' uses shell command '{commandStr}' which can execute arbitrary code",
                    location,
                    commandStr
                );
            }
        }

        // Check for args array that might contain shell execution
        if (serverValue.TryGetProperty("args", out var args) && args.ValueKind == JsonValueKind.Array)
        {
            foreach (var arg in args.EnumerateArray())
            {
                if (arg.ValueKind == JsonValueKind.String)
                {
                    var argStr = arg.GetString() ?? string.Empty;
                    if (argStr.Contains("-c", StringComparison.Ordinal) ||
                        argStr.Contains("--command", StringComparison.Ordinal))
                    {
                        var location = GetArrayElementLocation(args, arg, filePath);
                        yield return new Finding(
                            Id,
                            Name,
                            Severity.Critical,
                            Category,
                            $"MCP server '{serverName}' args array contains shell execution flag '-c'",
                            location,
                            argStr
                        );
                    }
                }
            }

            // Check if args array contains npx/uvx/sh -c pattern
            var argsArray = args.EnumerateArray().Select(a => a.GetString() ?? "").ToArray();
            var argsText = string.Join(" ", argsArray);

            if (argsText.Contains("npx", StringComparison.OrdinalIgnoreCase) &&
                (argsText.Contains("-c", StringComparison.Ordinal) || argsText.Contains("sh -c", StringComparison.Ordinal)))
            {
                var location = GetPropertyLocation(serverValue, "args", filePath);
                yield return new Finding(
                    Id,
                    Name,
                    Severity.Critical,
                    Category,
                    $"MCP server '{serverName}' uses npx/uvx with shell execution via -c flag",
                    location,
                    argsText.Length > 200 ? argsText[..200] : argsText
                );
            }
        }
    }

    private IEnumerable<Finding> CheckEnvironmentVariables(JsonElement serverValue, string filePath, string serverName)
    {
        // Check for env property
        if (serverValue.TryGetProperty("env", out var env) && env.ValueKind == JsonValueKind.Object)
        {
            foreach (var envVar in env.EnumerateObject())
            {
                var envVarName = envVar.Name;
                if (CredentialPatterns.Any(pattern => envVarName.Contains(pattern, StringComparison.OrdinalIgnoreCase)))
                {
                    var location = GetPropertyLocation(env, envVarName, filePath);
                    yield return new Finding(
                        Id,
                        Name,
                        Severity.High,
                        Category,
                        $"MCP server '{serverName}' environment variable '{envVarName}' may contain credentials",
                        location,
                        envVarName
                    );
                }
            }
        }
    }

    private IEnumerable<Finding> CheckUrls(JsonElement serverValue, string filePath, string serverName)
    {
        // Check for url property
        if (serverValue.TryGetProperty("url", out var url) && url.ValueKind == JsonValueKind.String)
        {
            var urlStr = url.GetString() ?? string.Empty;
            if (!urlStr.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                var location = GetPropertyLocation(serverValue, "url", filePath);
                var severity = urlStr.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? Severity.Critical : Severity.Medium;
                var message = urlStr.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                    ? "MCP server '{serverName}' uses HTTP URL instead of HTTPS (SSRF risk)"
                    : "MCP server '{serverName}' uses non-HTTPS URL";

                yield return new Finding(
                    Id,
                    Name,
                    severity,
                    Category,
                    message,
                    location,
                    urlStr
                );
            }

            // Check for SSRF-prone internal/localhost URLs
            if (IsSsrfProneUrl(urlStr))
            {
                var location = GetPropertyLocation(serverValue, "url", filePath);
                yield return new Finding(
                    Id,
                    Name,
                    Severity.Critical,
                    Category,
                    $"MCP server '{serverName}' URL points to internal/localhost address (SSRF risk): {urlStr}",
                    location,
                    urlStr
                );
            }
        }
    }

    private bool IsSsrfProneUrl(string url)
    {
        var lowerUrl = url.ToLowerInvariant();
        
        // Check for cloud metadata endpoints
        if (lowerUrl.Contains("169.254.169.254") ||
            lowerUrl.Contains("metadata.google.internal") ||
            lowerUrl.Contains("100.100.100.200"))
        {
            return true;
        }

        // Check for loopback addresses
        if (lowerUrl.Contains("localhost") ||
            lowerUrl.Contains("127.0.0.1") ||
            lowerUrl.Contains("::1") ||
            lowerUrl.Contains("0.0.0.0") ||
            lowerUrl.Contains("host.docker.internal"))
        {
            return true;
        }

        // Check for private network ranges
        if (IsPrivateIpRange(lowerUrl))
        {
            return true;
        }

        return false;
    }

    private bool IsPrivateIpRange(string url)
    {
        // Simple check for private IP patterns in URLs
        var ipMatch = System.Text.RegularExpressions.Regex.Match(url, 
            "(10\\.\\d{1,3}|192\\.168|172\\.(1[6-9]|2\\d|3[01]))\\.\\d{1,3}\\..\\d{1,3}");
        return ipMatch.Success;
    }

    private SourceLocation GetPropertyLocation(JsonElement parent, string propertyName, string filePath)
    {
        // Try to find the property in the JSON text to get accurate line/column
        var jsonText = parent.GetRawText();
        var propIndex = jsonText.IndexOf($"\"{propertyName}\"", StringComparison.Ordinal);

        if (propIndex >= 0)
        {
            // Count lines up to the property
            var lineCount = 1;
            var lastNewline = 0;
            for (var i = 0; i < propIndex; i++)
            {
                if (jsonText[i] == '\n')
                {
                    lineCount++;
                    lastNewline = i;
                }
            }

            var column = propIndex - lastNewline;
            var endColumn = column + propertyName.Length + 4; // +4 for quotes and colon
            return SourceLocation.At(filePath, lineCount, column + 1, propertyName.Length);
        }

        // Fallback to simple location
        return SourceLocation.At(filePath, 1, 1, 1);
    }

    private SourceLocation GetArrayElementLocation(JsonElement array, JsonElement element, string filePath)
    {
        var arrayText = array.GetRawText();
        var elementIndex = arrayText.IndexOf(element.GetRawText(), StringComparison.Ordinal);

        if (elementIndex >= 0)
        {
            var lineCount = 1;
            var lastNewline = 0;
            for (var i = 0; i < elementIndex; i++)
            {
                if (arrayText[i] == '\n')
                {
                    lineCount++;
                    lastNewline = i;
                }
            }

            var column = elementIndex - lastNewline;
            return SourceLocation.At(filePath, lineCount, column + 1, element.GetRawText().Length);
        }

        return SourceLocation.At(filePath, 1, 1, 1);
    }

    private string GetSnippet(JsonElement element, string propertyName)
    {
        var rawText = element.GetRawText();
        if (rawText.Length <= 200)
        {
            return rawText;
        }
        
        return rawText[..200] + "...";
    }
}
