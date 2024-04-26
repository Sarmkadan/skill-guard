using System.Text.Json;

namespace SkillGuard.Core;

/// <summary>
/// Provides JSON serialization helpers for the <see cref="SarifReporter"/> type.
/// </summary>
public static class SarifReporterJsonExtensions
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    /// <summary>
    /// Serializes a <see cref="SarifReporter"/> to a JSON string.
    /// </summary>
    /// <param name="value">The reporter to serialize.</param>
    /// <param name="indented">If true, formats the JSON with indentation.</param>
    /// <returns>A JSON string representation of the reporter.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public static string ToJson(this SarifReporter value, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        
        var options = new JsonSerializerOptions(JsonOptions)
        {
            WriteIndented = indented
        };
        
        return JsonSerializer.Serialize(value, options);
    }

    /// <summary>
    /// Deserializes a <see cref="SarifReporter"/> from a JSON string.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <returns>A deserialized <see cref="SarifReporter"/> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null or empty.</exception>
    /// <exception cref="JsonException">Thrown when JSON deserialization fails.</exception>
    public static SarifReporter? FromJson(string json)
    {
        ArgumentException.ThrowIfNullOrEmpty(json);
        
        return JsonSerializer.Deserialize<SarifReporter>(json, JsonOptions);
    }

    /// <summary>
    /// Tries to deserialize a <see cref="SarifReporter"/> from a JSON string.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <param name="value">The deserialized <see cref="SarifReporter"/> if successful; otherwise null.</param>
    /// <returns>True if deserialization succeeded; otherwise false.</returns>
    public static bool TryFromJson(string json, out SarifReporter? value)
    {
        try
        {
            ArgumentException.ThrowIfNullOrEmpty(json);
            
            value = JsonSerializer.Deserialize<SarifReporter>(json, JsonOptions);
            return value is not null;
        }
        catch (JsonException)
        {
            value = null;
            return false;
        }
    }
}
