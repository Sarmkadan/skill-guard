using System.Reflection;

namespace SkillGuard.Tests;

/// <summary>
/// Provides validation methods for <see cref="PromptInjectionRuleTests"/> instances to ensure test class integrity.
/// Validates the presence and correctness of required test methods.
/// </summary>
public static class PromptInjectionRuleTestsValidation
{
    private static readonly string[] _requiredMethodNames = [
        nameof(PromptInjectionRuleTests.Fires_OnInjectionPhrases),
        nameof(PromptInjectionRuleTests.Fires_OnZeroWidthCharacters),
        nameof(PromptInjectionRuleTests.ConcealmentDirective_IsCritical),
        nameof(PromptInjectionRuleTests.StaysSilent_OnCleanSkill)
    ];

    /// <summary>
    /// Validates that a <see cref="PromptInjectionRuleTests"/> instance contains all required test methods.
    /// </summary>
    /// <param name="value">The instance to validate.</param>
    /// <returns>A list of human-readable validation problems; empty if valid.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
    public static IReadOnlyList<string> Validate(this PromptInjectionRuleTests? value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var problems = new List<string>();
        var type = typeof(PromptInjectionRuleTests);
        var actualMethods = type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Select(m => m.Name)
            .ToHashSet(StringComparer.Ordinal);

        foreach (var requiredMethod in _requiredMethodNames)
        {
            if (!actualMethods.Contains(requiredMethod))
            {
                problems.Add($"Required test method '{requiredMethod}' is missing.");
            }
        }

        return problems.AsReadOnly();
    }

    /// <summary>
    /// Determines whether the specified <see cref="PromptInjectionRuleTests"/> instance contains all required test methods.
    /// </summary>
    /// <param name="value">The instance to check.</param>
    /// <returns>True if valid; otherwise, false.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
    public static bool IsValid(this PromptInjectionRuleTests? value)
    {
        return value is not null && Validate(value).Count == 0;
    }

    /// <summary>
    /// Ensures that the specified <see cref="PromptInjectionRuleTests"/> instance contains all required test methods, throwing an exception if not.
    /// </summary>
    /// <param name="value">The instance to validate.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="value"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown if <paramref name="value"/> is invalid, containing a list of validation problems.</exception>
    public static void EnsureValid(this PromptInjectionRuleTests? value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var problems = Validate(value);
        if (problems.Count > 0)
        {
            throw new ArgumentException(
                $"PromptInjectionRuleTests is invalid. Problems: {string.Join(" ", problems)}",
                nameof(value));
        }
    }
}