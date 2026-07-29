using System.Collections.Generic;

namespace SkillGuard.Core
{
    public interface IRuleEngine
    {
        IReadOnlyList<IScanRule> Rules { get; }
        ScanReport Scan(IEnumerable<ScanTarget> targets);
    }
}
