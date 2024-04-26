using System.Text.Json;

namespace SkillGuard.Core;

/// <summary>
/// Provides JSON serialization helpers for the <see cref="SourceLocation"/> type.
/// </summary>
public static class SourceLocationJsonExtensions
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    /// <summary>
    /// Serializes a <see cref="SourceLocation"/> to a JSON string.
    /// </summary>
    /// <param name="value">The source location to serialize.</param>
    /// <param name="indented">If true, formats the JSON with indentation.</param>
    /// <returns>A JSON string representation of the source location.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="value"/> is null.</exception>
    public static string ToJson(this SourceLocation value, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        
        var options = new JsonSerializerOptions(JsonOptions)
        {
            WriteIndented = indented
        };
        
        return JsonSerializer.Serialize(value, options);
    }

    /// <summary>
    /// Deserializes a <see cref="SourceLocation"/> from a JSON string.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <returns>A deserialized <see cref="SourceLocation"/> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null or empty.</exception>
    /// <exception cref="JsonException">Thrown when JSON deserialization fails.</exception>
    public static SourceLocation? FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        
        return JsonSerializer.Deserialize<SourceLocation>(json, JsonOptions);
    }

    /// <summary>
    /// Tries to deserialize a <see cref="SourceLocation"/> from a JSON string.
    /// </summary>
    /// <param name="json">The JSON string to deserialize.</param>
    /// <param name="value">The deserialized <see cref="SourceLocation"/> if successful; otherwise null.</param>
    /// <returns>True if deserialization succeeded; otherwise false.</returns>
    public static bool TryFromJson(string json, out SourceLocation? value)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(json);
            
            value = JsonSerializer.Deserialize<SourceLocation>(json, JsonOptions);
            return value is not null;
        }
        catch (JsonException)
        {
            value = null;
            return false;
        }
    }
}
