namespace SkillGuard.Tests;

public interface IRuleEngineTests
{
    void Scan_OrdersFindingsBySeverityThenLocation();
    void Scan_CleanSkillProducesNoFindings();
    void CountAtOrAbove_FiltersBySeverity();
    void RuleCatalog_ExposesRulesSg001ThroughSg011();
    void RuleCatalog_HasUniqueRuleIds();
    void RuleCatalog_Filter_DisablesRulesCaseInsensitively();
}
