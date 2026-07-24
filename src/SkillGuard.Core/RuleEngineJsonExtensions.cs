using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SkillGuard.Core;

public static class RuleEngineJsonExtensions
{
    private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    public static string ToJson(this RuleEngine value, bool indented = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (indented)
        {
            _jsonOptions.WriteIndented = true;
        }
        return JsonSerializer.Serialize(value, _jsonOptions);
    }

    public static RuleEngine? FromJson(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            return JsonSerializer.Deserialize<RuleEngine>(json, _jsonOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public static bool TryFromJson(string json, out RuleEngine? value)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            value = JsonSerializer.Deserialize<RuleEngine>(json, _jsonOptions);
            return true;
        }
        catch (JsonException)
        {
            value = null;
            return false;
        }
    }
}
