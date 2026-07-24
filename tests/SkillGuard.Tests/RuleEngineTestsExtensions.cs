using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Xunit;

namespace SkillGuard.Tests;

/// <summary>
/// Extension methods that provide reflection‑based helpers for the <see cref="RuleEngineTests"/> test class.
/// </summary>
public static class RuleEngineTestsExtensions
{
    /// <summary>
    /// Gets the names of all public instance test methods declared directly on <see cref="RuleEngineTests"/>.
    /// </summary>
    /// <param name="tests">The <see cref="RuleEngineTests"/> instance.</param>
    /// <returns>An <see cref="IReadOnlyList{T}"/> containing the method names.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="tests"/> is <c>null</c>.</exception>
    public static IReadOnlyList<string> GetTestMethodNames(this RuleEngineTests tests)
    {
        ArgumentNullException.ThrowIfNull(tests);
        return typeof(RuleEngineTests)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Select(m => m.Name)
            .ToArray();
    }

    /// <summary>
    /// Gets the total number of public instance test methods declared directly on <see cref="RuleEngineTests"/>.
    /// </summary>
    /// <param name="tests">The <see cref="RuleEngineTests"/> instance.</param>
    /// <returns>The count of test methods.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="tests"/> is <c>null</c>.</exception>
    public static int GetTestMethodCount(this RuleEngineTests tests) =>
        tests.GetTestMethodNames().Count;

    /// <summary>
    /// Returns the <see cref="MethodInfo"/> objects for all public instance test methods that are
    /// decorated with the specified attribute type (e.g., <see cref="FactAttribute"/> or <see cref="TheoryAttribute"/>).
    /// </summary>
    /// <typeparam name="TAttribute">The attribute type to filter by.</typeparam>
    /// <param name="tests">The <see cref="RuleEngineTests"/> instance.</param>
    /// <returns>An <see cref="IEnumerable{MethodInfo}"/> of matching methods.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="tests"/> is <c>null</c>.</exception>
    public static IEnumerable<MethodInfo> GetTestMethodsWithAttribute<TAttribute>(this RuleEngineTests tests)
        where TAttribute : Attribute
    {
        ArgumentNullException.ThrowIfNull(tests);
        return typeof(RuleEngineTests)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes(typeof(TAttribute), inherit: false).Any());
    }
}
