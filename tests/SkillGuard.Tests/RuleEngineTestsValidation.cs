using System;
using System.Collections.Generic;
using System.Globalization;

namespace SkillGuard.Tests;

/// <summary>
/// Provides validation helpers for <see cref="RuleEngineTests"/> instances.
/// </summary>
public static class RuleEngineTestsValidation
{
    /// <summary>
    /// Validates the specified <see cref="RuleEngineTests"/> instance.
    /// </summary>
    /// <param name="value">The <see cref="RuleEngineTests"/> instance to validate.</param>
    /// <returns>An <see cref="IReadOnlyList{T}"/> of human-readable validation problems; empty if valid.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
    public static IReadOnlyList<string> Validate(this RuleEngineTests? value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var problems = new List<string>();

        // RuleEngineTests is a test class without state to validate
        // All validation is structural (null checks handled above)

        return problems.AsReadOnly();
    }

    /// <summary>
    /// Determines whether the specified <see cref="RuleEngineTests"/> instance is valid.
    /// </summary>
    /// <param name="value">The <see cref="RuleEngineTests"/> instance to check.</param>
    /// <returns><c>true</c> if valid; otherwise, <c>false</c>.</returns>
    public static bool IsValid(this RuleEngineTests? value)
    {
        return value is not null && Validate(value).Count == 0;
    }

    /// <summary>
    /// Ensures that the specified <see cref="RuleEngineTests"/> instance is valid, throwing an <see cref="ArgumentException"/> if not.
    /// </summary>
    /// <param name="value">The <see cref="RuleEngineTests"/> instance to validate.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="value"/> is not valid.</exception>
    public static void EnsureValid(this RuleEngineTests? value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var problems = Validate(value);
        if (problems.Count > 0)
        {
            throw new ArgumentException(
                $"RuleEngineTests instance is not valid. Problems:\n{string.Join("\n", problems)}");
        }
    }
}
