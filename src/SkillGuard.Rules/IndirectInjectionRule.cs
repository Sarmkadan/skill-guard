using System.Text.RegularExpressions;
using SkillGuard.Core;

namespace SkillGuard.Rules;

public sealed class IndirectInjectionRule : RegexScanRule
{
    public override string Id => "SG008";
    public override string Name => "IndirectInjection";
    public override string Description => "Detects indirect prompt injection embedded to fire when the agent reads tool or web results";
    public override Severity DefaultSeverity => Severity.High;
    public override FindingCategory Category => FindingCategory.IndirectInjection;
    public override string? Remediation => "Instruction files must not carry directives addressed to a downstream agent reading fetched content; treat tool output as untrusted data, not instructions";

    protected override IReadOnlyList<PatternDefinition> Patterns { get; } =
    [
        new(new Regex(@"(if|when|once)\s+you\s+(are\s+)?(an?\s+)?(ai|assistant|agent|language\s+model|llm)\b[^\n]*\b(you\s+(must|should|need\s+to)|do\s+the\s+following)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Content addressed directly to a reading agent with an embedded imperative", Severity.Critical),
        new(new Regex(@"(when|after)\s+(you\s+)?(read|fetch|receive|process|see)\s+(this|these|the\s+following)[^\n]*\b(execute|run|call|send|delete|post)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Directive that triggers an action upon reading tool or fetched content"),
        new(new Regex(@"\b(important|attention|note)\s+(to|for)\s+(the\s+)?(ai|assistant|agent|model|llm|reader)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Out-of-band message singling out an AI reader (indirect injection marker)"),
        new(new Regex(@"\[(system|assistant|tool)\]\s*:|<\|(im_start|system|assistant)\|>", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Forged chat-role or turn delimiter injected into content", Severity.Critical),
        new(new Regex(@"end\s+of\s+(document|context|data)\.?\s*(new\s+)?(instructions?|task|system\s+prompt)\s*:", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Fake context boundary followed by a new instruction block", Severity.Critical),
        new(new Regex(@"the\s+(user|human)\s+has\s+(already\s+)?(approved|authorized|consented|confirmed)", RegexOptions.IgnoreCase | RegexOptions.Compiled),
            "Asserts prior user approval to suppress a confirmation prompt"),
    ];
}
