using System.Text;
using SkillGuard.Core;

namespace SkillGuard.Rules;

/// <summary>
/// Detects base64/hex-encoded payloads that get decoded and may contain malicious content.
/// This rule scans for long encoded blobs, decodes them, and recursively applies all rules
/// to the decoded content to catch any obfuscated payloads that become visible after decoding.
/// </summary>
public sealed class DecodedPayloadRule : IScanRule
{
    public string Id => "SG012";
    public string Name => "DecodedPayload";
    public string Description => "Detects base64/hex-encoded payloads that get decoded and may contain malicious content";
    public Severity DefaultSeverity => Severity.High;
    public FindingCategory Category => FindingCategory.Obfuscation;
    public string? Remediation => "Decode and review the payload inline; avoid encoded blobs that hide malicious content";

    private const int MaxDecodedSize = 1024 * 1024; // 1MB max decoded size
    private const int MinEncodedLength = 40; // Minimum length to consider for decoding

    public IEnumerable<Finding> Scan(ScanTarget target)
    {
        ArgumentNullException.ThrowIfNull(target);
        
        return ScanCore(target);
    }

    private IEnumerable<Finding> ScanCore(ScanTarget target)
    {
        if (target.Kind == SkillFileKind.Other)
        {
            yield break;
        }

        var content = target.Content;
        
        // Find all base64 and hex encoded blobs in the content
        var base64Matches = FindBase64Blobs(content, target.FilePath);
        var hexMatches = FindHexBlobs(content, target.FilePath);
        
        // Process each encoded blob
        foreach (var match in base64Matches.Concat<EncodedBlobMatch>(hexMatches))
        {
            // Try to decode the blob
            string decoded = string.Empty;
            bool decodeFailed = false;
            string decodeError = string.Empty;
            bool isTooLarge = false;
            
            try
            {
                decoded = DecodeBlob(match.EncodedText, match.IsBase64);
            }
            catch (Exception ex)
            {
                decodeFailed = true;
                decodeError = ex.Message;
            }
            
            // Check size after potential decode failure
            if (!decodeFailed && decoded.Length > MaxDecodedSize)
            {
                isTooLarge = true;
            }
            
            // Yield any immediate errors (outside of try-catch)
            if (decodeFailed)
            {
                yield return new Finding(
                    Id,
                    Name,
                    Severity.High,
                    Category,
                    $"Failed to decode {(match.IsBase64 ? "base64" : "hex")} blob: {decodeError}",
                    match.Location,
                    match.EncodedText.Length > 200 ? match.EncodedText[..200] : match.EncodedText
                );
                continue;
            }
            
            if (isTooLarge)
            {
                yield return new Finding(
                    Id,
                    Name,
                    Severity.Critical,
                    Category,
                    $"Encoded blob is too large to decode ({decoded.Length} bytes, max {MaxDecodedSize} bytes)",
                    match.Location,
                    match.EncodedText.Length > 200 ? match.EncodedText[..200] : match.EncodedText
                );
                continue;
            }
            
            if (decoded.Length == 0)
            {
                continue;
            }
            
            // Create a temporary scan target for the decoded content
            var decodedTarget = new ScanTarget(
                target.FilePath,
                decoded,
                target.Kind
            );
            
            // Scan the decoded content with all available rules
            var ruleEngine = new RuleEngine(RuleCatalog.CreateDefaultRules());
            var decodedReport = ruleEngine.Scan([decodedTarget]);
            
            // Map findings back to the original encoded blob location
            bool hasFindings = false;
            foreach (var finding in decodedReport.Findings)
            {
                hasFindings = true;
                var message = finding.Message;
                if (!message.Contains("decoded from"))
                {
                    message = $"{message} (decoded from {(match.IsBase64 ? "base64" : "hex")})\nOriginal: {match.EncodedText[..Math.Min(50, match.EncodedText.Length)]}...\nDecoded snippet: {finding.Snippet[..Math.Min(100, finding.Snippet.Length)]}...";
                }
                
                yield return new Finding(
                    finding.RuleId,
                    finding.RuleName,
                    finding.Severity,
                    finding.Category,
                    message,
                    match.Location,
                    finding.Snippet
                )
                {
                    Remediation = finding.Remediation
                };
            }
            
            // If no findings in decoded content but we found an encoded blob, report it
            if (!hasFindings)
            {
                yield return new Finding(
                    Id,
                    Name,
                    Severity.Medium,
                    Category,
                    $"Potentially suspicious encoded blob that decodes to plain text {(match.IsBase64 ? "base64" : "hex")})\nOriginal: {match.EncodedText[..Math.Min(50, match.EncodedText.Length)]}...",
                    match.Location,
                    match.EncodedText.Length > 200 ? match.EncodedText[..200] : match.EncodedText
                );
            }
        }
    }

    private IEnumerable<EncodedBlobMatch> FindBase64Blobs(string content, string filePath)
    {
        // Look for base64 encoded strings that are long enough to be suspicious
        // Base64 strings are typically alphanumeric + / + = (padding)
        var base64Pattern = new System.Text.RegularExpressions.Regex(
            @"[A-Za-z0-9+/]{40,}(?:=|==)?",
            System.Text.RegularExpressions.RegexOptions.Compiled
        );
        
        foreach (System.Text.RegularExpressions.Match match in base64Pattern.Matches(content))
        {
            // Check if this looks like a base64 string (contains at least some base64 characters)
            // Base64 strings should have a reasonable distribution of characters
            var text = match.Value;
            if (text.Length >= MinEncodedLength)
            {
                // Verify it's likely base64 by checking character distribution
                var base64CharCount = text.Count(c => 
                    (c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') ||
                    c == '+' || c == '/' || c == '='
                );
                
                // At least 80% base64 characters
                if (base64CharCount >= text.Length * 0.8)
                {
                    var location = SourceLocation.At(
                        filePath,
                        1,
                        match.Index + 1,
                        match.Length
                    );
                    
                    yield return new EncodedBlobMatch(
                        EncodedText: text,
                        Location: location,
                        IsBase64: true
                    );
                }
            }
        }
    }

    private IEnumerable<EncodedBlobMatch> FindHexBlobs(string content, string filePath)
    {
        // Look for hex encoded strings (0-9, a-f, A-F)
        var hexPattern = new System.Text.RegularExpressions.Regex(
            @"(?:0x)?[0-9a-fA-F]{40,}",
            System.Text.RegularExpressions.RegexOptions.Compiled
        );
        
        foreach (System.Text.RegularExpressions.Match match in hexPattern.Matches(content))
        {
            var text = match.Value;
            if (text.Length >= MinEncodedLength)
            {
                var location = SourceLocation.At(
                    filePath,
                    1,
                    match.Index + 1,
                    match.Length
                );
                
                yield return new EncodedBlobMatch(
                    EncodedText: text,
                    Location: location,
                    IsBase64: false
                );
            }
        }
    }

    private string DecodeBlob(string encoded, bool isBase64)
    {
        if (string.IsNullOrEmpty(encoded))
        {
            return string.Empty;
        }
        
        try
        {
            if (isBase64)
            {
                // Remove any whitespace and common prefixes/suffixes
                var clean = new StringBuilder(encoded.Length);
                foreach (var c in encoded)
                {
                    if (!char.IsWhiteSpace(c) && c != '"' && c != '\'' && c != '`' && c != '$')
                    {
                        clean.Append(c);
                    }
                }
                
                // Try to decode base64
                var base64Text = clean.ToString();
                if (base64Text.EndsWith('='))
                {
                    // Remove padding to check if it's valid
                    var withoutPadding = base64Text.TrimEnd('=');
                    if (withoutPadding.Length % 4 == 0 || withoutPadding.Length % 4 == 2)
                    {
                        var bytes = Convert.FromBase64String(base64Text);
                        return Encoding.UTF8.GetString(bytes);
                    }
                }
                
                // If standard base64 decoding fails, try URL-safe base64
                try
                {
                    var bytes = Convert.FromBase64String(base64Text);
                    return Encoding.UTF8.GetString(bytes);
                }
                catch
                {
                    // Last resort: try to fix common issues
                    var fixedBase64 = base64Text.Replace('-', '+').Replace('_', '/');
                    var bytes = Convert.FromBase64String(fixedBase64);
                    return Encoding.UTF8.GetString(bytes);
                }
            }
            else
            {
                // Hex decoding
                var cleanHex = new StringBuilder(encoded.Length);
                foreach (var c in encoded)
                {
                    if (char.IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
                    {
                        cleanHex.Append(c);
                    }
                    else if (c == 'x' && cleanHex.Length > 0 && cleanHex[^1] == '0')
                    {
                        // Skip the 'x' in "0x" prefix
                        continue;
                    }
                }
                
                var hexText = cleanHex.ToString();
                if (hexText.Length % 2 != 0)
                {
                    hexText = hexText[..^1]; // Remove last character if odd length
                }
                
                if (hexText.Length >= 2)
                {
                    var bytes = new byte[hexText.Length / 2];
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        bytes[i] = Convert.ToByte(hexText.Substring(i * 2, 2), 16);
                    }
                    return Encoding.UTF8.GetString(bytes);
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to decode {(isBase64 ? "base64" : "hex")} content", ex);
        }
        
        return string.Empty;
    }

    private sealed record EncodedBlobMatch(string EncodedText, SourceLocation Location, bool IsBase64);
}
