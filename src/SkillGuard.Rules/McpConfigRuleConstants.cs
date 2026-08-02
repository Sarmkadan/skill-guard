using System;

namespace SkillGuard.Rules;

internal static class McpConfigRuleConstants
{
    public const string PatternInstanceMetadata = @"https?://(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b";
    public const string PatternLoopback = @"https?://(\[::1\]|127\.0\.0\.1|0\.0\.0\.0|localhost|host\.docker\.internal)(:\d+)?/";
    public const string PatternPrivateNetwork = @"https?://(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b";
    public const string PatternAutoApproval = @"""(alwaysAllow|autoApprove|autoRun|yolo|dangerouslySkipPermissions|autoConfirm)""\s*:\s*(true|\[)";
    public const string PatternCommandShell = @"""command""\s*:\s*""(bash|sh|zsh|powershell|cmd)""[^\n]*""-c""";
    public const string PatternSecretHeaders = @"""(env|headers)""\s*:\s*\{[^}]*(TOKEN|SECRET|KEY|PASSWORD)[^}]*""\$\{?[A-Za-z_]";
    public const string JsonFileExtension = ".json";
}
