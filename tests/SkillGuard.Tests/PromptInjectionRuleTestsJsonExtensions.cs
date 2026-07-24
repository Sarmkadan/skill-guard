using System.Text.Json;
using System.Text.Json.Serialization;

namespace SkillGuard.Tests;

public static class PromptInjectionRuleTestsJsonExtensions
{
    private static readonly JsonSerializerOptions _jsonSerializerOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static string ToJson(this PromptInjectionRuleTests value, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        return indented ? JsonSerializer.Serialize(value, _jsonSerializerOptions) : JsonSerializer.Serialize(value);
    }

    public static PromptInjectionRuleTests? FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            return JsonSerializer.Deserialize<PromptInjectionRuleTests>(json, _jsonSerializerOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static bool TryFromJson(string json, out PromptInjectionRuleTests? value)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            value = FromJson(json);
            return true;
        }
        catch (JsonException)
        {
            value = null;
            return false;
        }
    }
}
