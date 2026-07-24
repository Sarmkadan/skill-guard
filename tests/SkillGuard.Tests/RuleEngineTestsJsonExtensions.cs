using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SkillGuard.Tests
{
    public static class RuleEngineTestsJsonExtensions
    {
        private static readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static readonly JsonSerializerOptions _indentedJsonOptions = new(JsonSerializerDefaults.Web)
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>
        /// Serializes a <see cref="RuleEngineTests"/> instance to a JSON string.
        /// </summary>
        /// <param name="value">The instance to serialize. Must not be null.</param>
        /// <param name="indented">Whether to format the JSON with indentation for readability.</param>
        /// <returns>A JSON string representation of the instance.</returns>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
        public static string ToJson(this RuleEngineTests value, bool indented = false)
        {
            ArgumentNullException.ThrowIfNull(value);

            return JsonSerializer.Serialize(value, indented ? _indentedJsonOptions : _jsonOptions);
        }

        /// <summary>
        /// Deserializes a JSON string to a <see cref="RuleEngineTests"/> instance.
        /// </summary>
        /// <param name="json">The JSON string to deserialize. Must not be null or empty.</param>
        /// <returns>The deserialized instance, or null if the JSON represents a null value.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="json"/> is null or empty.</exception>
        /// <exception cref="JsonException">Thrown when the JSON is invalid or cannot be deserialized to <see cref="RuleEngineTests"/>.</exception>
        public static RuleEngineTests? FromJson(string json)
        {
            ArgumentException.ThrowIfNullOrEmpty(json);

            return JsonSerializer.Deserialize<RuleEngineTests>(json, _jsonOptions);
        }

        /// <summary>
        /// Attempts to deserialize a JSON string to a <see cref="RuleEngineTests"/> instance.
        /// </summary>
        /// <param name="json">The JSON string to deserialize. Must not be null or empty.</param>
        /// <param name="value">Receives the deserialized instance, or null if deserialization fails.</param>
        /// <returns>True if deserialization succeeded; otherwise, false.</returns>
        /// <exception cref="ArgumentException">Thrown when <paramref name="json"/> is null or empty.</exception>
        public static bool TryFromJson(string json, out RuleEngineTests? value)
        {
            ArgumentException.ThrowIfNullOrEmpty(json);

            try
            {
                value = JsonSerializer.Deserialize<RuleEngineTests>(json, _jsonOptions);
                return true;
            }
            catch (JsonException)
            {
                value = default;
                return false;
            }
        }
    }
}