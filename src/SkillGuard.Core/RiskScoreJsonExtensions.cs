using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace SkillGuard.Core;

/// <summary>
/// Provides System.Text.Json serialization and deserialization helpers for <see cref="RiskScore"/>.
/// </summary>
public static class RiskScoreJsonExtensions
{
    private static readonly JsonSerializerOptions _options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
        WriteIndented = false
    };

    /// <summary>
    /// Serializes a <see cref="RiskScore"/> to a JSON string.
    /// </summary>
    /// <param name="value">The risk score to serialize</param>
    /// <param name="indented">Whether to format the JSON with indentation for readability</param>
    /// <returns>A JSON string representation of the risk score</returns>
    /// <exception cref="ArgumentNullException">Thrown if value is null</exception>
    public static string ToJson(this RiskScore value, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(value);

        var options = indented
            ? new JsonSerializerOptions(_options) { WriteIndented = true }
            : _options;

        return JsonSerializer.Serialize(value, options);
    }

    /// <summary>
    /// Deserializes a JSON string into a <see cref="RiskScore"/> instance.
    /// </summary>
    /// <param name="json">The JSON string to deserialize</param>
    /// <returns>The deserialized risk score, or null if the JSON is null or empty</returns>
    /// <exception cref="JsonException">Thrown if the JSON is malformed or cannot be deserialized</exception>
    public static RiskScore? FromJson(string json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return null;
        }

        return JsonSerializer.Deserialize<RiskScore>(json, _options);
    }

    /// <summary>
    /// Attempts to deserialize a JSON string into a <see cref="RiskScore"/> instance.
    /// </summary>
    /// <param name="json">The JSON string to deserialize</param>
    /// <param name="value">Receives the deserialized risk score if successful</param>
    /// <returns>True if deserialization succeeded; otherwise, false</returns>
    public static bool TryFromJson(string json, out RiskScore? value)
    {
        value = null;

        if (string.IsNullOrEmpty(json))
        {
            return true;
        }

        try
        {
            value = JsonSerializer.Deserialize<RiskScore>(json, _options);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}