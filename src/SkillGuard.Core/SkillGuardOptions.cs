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

    /// <summary>Additional egress hosts to allow beyond the built-in allowlist (hostnames only).</summary>
    public IReadOnlyList<string> AllowedHosts { get; init; } = [];

    /// <summary>Rule ids to disable (for example <c>SG005</c>). Matched case-insensitively.</summary>
    public IReadOnlyList<string> DisabledRuleIds { get; init; } = [];

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

        return errors;
    }

    private static bool IsValidHostname(string? host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > MaxHostnameLength) return false;

        return host.Split('.').All(label => HostLabelPattern.IsMatch(label));
    }
}
