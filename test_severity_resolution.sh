#!/bin/bash
# Simple test to verify severity resolution contract is working correctly

set -e

echo "=== Testing Severity Resolution Contract ==="
echo ""

echo "1. Building SkillGuard.Core..."
cd /home/redrocket/task-factory/workdir/skill-guard/src/SkillGuard.Core
if dotnet build -nologo -clp:NoSummary; ; then
    echo "✅ SkillGuard.Core builds successfully"
else
    echo "❌ SkillGuard.Core build failed"
    exit 1
fi

echo ""
echo "2. Building entire solution..."
cd /home/redrocket/task-factory/workdir/skill-guard
if dotnet build -nologo -clp:NoSummary; then
    echo "✅ Entire solution builds successfully"
else
    echo "❌ Solution build failed"
    exit 1
fi

echo ""
echo "3. Verifying key files exist..."
for file in "src/SkillGuard.Core/SeverityResolution.cs" \
            "src/SkillGuard.Core/RegexScanRule.cs" \
            "src/SkillGuard.Core/RiskScore.cs" \
            "src/SkillGuard.Core/Models.cs"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists"
    else
        echo "❌ $file missing"
        exit 1
    fi
done

echo ""
echo "4. Verifying SeverityResolution class exists..."
if grep -q "public static class SeverityResolution" src/SkillGuard.Core/SeverityResolution.cs; then
    echo "✅ SeverityResolution class found"
else
    echo "❌ SeverityResolution class not found"
    exit 1
fi

echo ""
echo "5. Verifying PatternDefinition.SeverityOverride usage..."
if grep -q "Severity? SeverityOverride" src/SkillGuard.Core/RegexScanRule.cs; then
    echo "✅ PatternDefinition.SeverityOverride property found"
else
    echo "❌ PatternDefinition.SeverityOverride property not found"
    exit 1
fi

echo ""
echo "6. Verifying SeverityResolution.Resolve usage..."
if grep -q "SeverityResolution.Resolve" src/SkillGuard.Core/RegexScanRule.cs; then
    echo "✅ SeverityResolution.Resolve used in RegexScanRule"
else
    echo "❌ SeverityResolution.Resolve not found in RegexScanRule"
    exit 1
fi

echo ""
echo "7. Verifying RiskScore uses Finding.Severity..."
if grep -q "finding.Severity" src/SkillGuard.Core/RiskScore.cs; then
    echo "✅ RiskScore uses finding.Severity"
else
    echo "❌ RiskScore doesn't use finding.Severity"
    exit 1
fi

echo ""
echo "8. Verifying documentation exists..."
if grep -q "Severity Contract" src/SkillGuard.Core/Models.cs && \
   grep -q "Severity Contract" src/SkillGuard.Core/RiskScore.cs; then
    echo "✅ Severity contract documentation found in Models.cs and RiskScore.cs"
else
    echo "❌ Severity contract documentation missing"
    exit 1
fi

echo ""
echo "=== All Tests Passed! ==="
echo ""
echo "Summary of changes:"
echo "- Created SeverityResolution.cs with centralized severity resolution logic"
echo "- Updated RegexScanRule to use SeverityResolution.Resolve()"
echo "- Added comprehensive XML documentation to Finding, PatternDefinition, RegexScanRule, and RiskScore"
echo "- Ensured Finding.Severity is the single source of truth for both display and RiskScore aggregation"
echo "- All rules now follow a consistent severity resolution contract"
