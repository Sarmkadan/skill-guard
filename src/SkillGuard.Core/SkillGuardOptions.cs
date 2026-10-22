using System.Text.RegularExpressions;

namespace SkillGuard.Core;

/// <summary>
/// Scanner settings supplied on the command line, validated once at startup before any file is scanned.
/// </summary>
public sealed class SkillGuardOptions
{
    /// <summary>Upper bound for <see cref="RegexTimeout"/>.</summary>
    public static readonly TimeSpan MaxRegexTimeout = TimeSpan.FromSeconds(30);

    private static readonly Regex HostLabelPattern = new(@"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z", RegexOptions.Compiled);

    private const int MaxHostnameLength = 253;

    /// <summary>Id of the credential exfiltration rule, which owns <see cref="CredentialFilePatterns"/>.</summary>
    private const string CredentialExfiltrationRuleId = "SG002";

    /// <summary>Additional egress hosts to allow beyond the built-in allowlist (hostnames only).</summary>
    public IReadOnlyList<string> AllowedHosts { get; init; } = [];

    /// <summary>Rule ids to disable (for example <c>SG005</c>). Matched case-insensitively.</summary>
    public IReadOnlyList<string> DisabledRuleIds { get; init; } = [];

    /// <summary>
    /// Regular expressions that identify sensitive files (for example <c>\.aws/credentials</c>) for the credential
    /// exfiltration rule (SG002). Null means the rule's built-in defaults. An empty list is only accepted when SG002 is
    /// disabled. Each entry must be a non-empty regex that does not match the empty string, and entries must be unique
    /// (case-insensitively, as matching is case-insensitive).
    /// </summary>
    public IReadOnlyList<string>? CredentialFilePatterns { get; init; }

    /// <summary>Per-match timeout for regular expressions. Must be greater than zero and at most <see cref="MaxRegexTimeout"/>.</summary>
    public TimeSpan RegexTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Largest file, in bytes, that will be scanned. Must be greater than zero.</summary>
    public long MaxFileSizeBytes { get; init; } = 1024 * 1024;

    /// <summary>
    /// Validates every field and returns one message per invalid field, or an empty list when the options are valid.
    /// </summary>
    /// <param name="knownRuleIds">The ids of all rules that exist in the rule catalog.</param>
    public IReadOnlyList<string> Validate(IEnumerable<string> knownRuleIds)
    {
        ArgumentNullException.ThrowIfNull(knownRuleIds);

        var known = new HashSet<string>(knownRuleIds, StringComparer.OrdinalIgnoreCase);
        var errors = new List<string>();

        for (var i = 0; i < AllowedHosts.Count; i++)
        {
            if (!IsValidHostname(AllowedHosts[i]))
            {
                errors.Add($"AllowedHosts[{i}] '{AllowedHosts[i]}' is not a valid hostname");
            }
        }

        for (var i = 0; i < DisabledRuleIds.Count; i++)
        {
            if (DisabledRuleIds[i] is null || !known.Contains(DisabledRuleIds[i]))
            {
                errors.Add($"DisabledRuleIds[{i}] '{DisabledRuleIds[i]}' is not a known rule id");
            }
        }

        if (RegexTimeout <= TimeSpan.Zero || RegexTimeout > MaxRegexTimeout)
        {
            errors.Add($"RegexTimeout {RegexTimeout} must be greater than 0 and at most {MaxRegexTimeout}");
        }

        if (MaxFileSizeBytes <= 0)
        {
            errors.Add($"MaxFileSizeBytes {MaxFileSizeBytes} must be greater than 0");
        }

        if (CredentialFilePatterns is { } patterns)
        {
            if (patterns.Count == 0 && !DisabledRuleIds.Contains(CredentialExfiltrationRuleId, StringComparer.OrdinalIgnoreCase))
            {
                errors.Add($"CredentialFilePatterns must not be empty unless {CredentialExfiltrationRuleId} is disabled");
            }

            ValidateCredentialFilePatterns(patterns, errors);
        }

        return errors;
    }

    private static void ValidateCredentialFilePatterns(IReadOnlyList<string> patterns, List<string> errors)
    {
        // Keyed case-insensitively because the rule compiles its patterns with RegexOptions.IgnoreCase.
        var firstIndexByPattern = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < patterns.Count; i++)
        {
            var pattern = patterns[i];

            if (string.IsNullOrWhiteSpace(pattern))
            {
                errors.Add($"CredentialFilePatterns[{i}] '{pattern}' must not be empty");
                continue;
            }

            if (firstIndexByPattern.TryGetValue(pattern, out var firstIndex))
            {
                errors.Add($"CredentialFilePatterns[{i}] '{pattern}' duplicates CredentialFilePatterns[{firstIndex}]");
                continue;
            }

            firstIndexByPattern[pattern] = i;

            try
            {
                if (new Regex(pattern, RegexOptions.IgnoreCase).IsMatch(string.Empty))
                {
                    errors.Add($"CredentialFilePatterns[{i}] '{pattern}' matches the empty string, which would flag every file read");
                }
            }
            catch (ArgumentException ex)
            {
                errors.Add($"CredentialFilePatterns[{i}] '{pattern}' is not a valid regular expression: {ex.Message}");
            }
        }
    }

    private static bool IsValidHostname(string? host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > MaxHostnameLength) return false;

        return host.Split('.').All(label => HostLabelPattern.IsMatch(label));
    }
}
