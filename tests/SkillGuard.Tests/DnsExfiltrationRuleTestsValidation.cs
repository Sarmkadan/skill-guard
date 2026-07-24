using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace SkillGuard.Tests
{
    /// <summary>
    /// Validation helpers for <see cref="DnsExfiltrationRuleTests"/>.
    /// </summary>
    public static class DnsExfiltrationRuleTestsValidation
    {
        /// <summary>
        /// Validates the <see cref="DnsExfiltrationRuleTests"/> instance and returns a list of validation errors.
        /// </summary>
        /// <param name="value">The <see cref="DnsExfiltrationRuleTests"/> instance to validate.</param>
        /// <returns>A read-only list of validation error messages, or an empty list if the instance is valid.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="value"/> is <see langword="null"/>.</exception>
        public static IReadOnlyList<string> Validate(this DnsExfiltrationRuleTests value)
        {
            ArgumentNullException.ThrowIfNull(value);
            // DnsExfiltrationRuleTests has no public fields or properties to validate.
            return Array.Empty<string>();
        }

        /// <summary>
        /// Determines whether the <see cref="DnsExfiltrationRuleTests"/> instance is valid.
        /// </summary>
        /// <param name="value">The <see cref="DnsExfiltrationRuleTests"/> instance to validate.</param>
        /// <returns><see langword="true"/> if the instance is valid; otherwise, <see langword="false"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="value"/> is <see langword="null"/>.</exception>
        public static bool IsValid(this DnsExfiltrationRuleTests value)
        {
            ArgumentNullException.ThrowIfNull(value);
            // DnsExfiltrationRuleTests has no public fields or properties to validate.
            return true;
        }

        /// <summary>
        /// Ensures the <see cref="DnsExfiltrationRuleTests"/> instance is valid, throwing an exception if it is not.
        /// </summary>
        /// <param name="value">The <see cref="DnsExfiltrationRuleTests"/> instance to validate.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="value"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">If the instance is invalid, containing a list of validation errors.</exception>
        public static void EnsureValid(this DnsExfiltrationRuleTests value)
        {
            ArgumentNullException.ThrowIfNull(value);
            var errors = Validate(value);
            if (errors.Count > 0)
            {
                throw new ArgumentException(string.Join(Environment.NewLine, errors), nameof(value));
            }
        }
    }
}