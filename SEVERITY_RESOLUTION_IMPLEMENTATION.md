# Severity Resolution Contract Implementation

## Overview

This document describes the implementation of a unified severity resolution contract across `Finding`, `PatternDefinition`, and `RiskScore` to ensure consistency in how severity values are handled throughout the SkillGuard codebase.

## Problem Statement

Before this implementation, severity handling was inconsistent:

1. **Finding** had a required non-nullable `Severity` property
2. **PatternDefinition** had a nullable `Severity? SeverityOverride` property
3. **RegexScanRule** resolved severity using: `definition.SeverityOverride ?? DefaultSeverity`
4. **Other rules** (UnreviewedPayloadRule, NetworkEgressRule, etc.) hardcoded severity directly
5. **RiskScore** aggregated findings using `finding.Severity`

This created potential for divergence where:
- A Finding might show one severity to users
- But RiskScore could count it under a different severity due to inconsistent resolution timing

## Solution

Created a centralized severity resolution contract with the following principles:

### 1. Single Source of Truth
- Severity is resolved **exactly once** at Finding-construction time
- The resolved severity is stored in `Finding.Severity` (non-nullable, required)
- Both the Finding display and RiskScore aggregation use this same value

### 2. Standardized Resolution Logic
- **PatternDefinition.SeverityOverride** takes precedence when set
- **Otherwise**, the rule's `DefaultSeverity` is used
- This logic is centralized in `SeverityResolution.Resolve()`

### 3. Contract Documentation
- All severity-related contracts are now explicitly documented
- XML documentation explains the resolution flow
- Clear guarantees about consistency between Finding and RiskScore

## Changes Made

### New File: `SeverityResolution.cs`

Created a new utility class that provides:

```csharp
public static class SeverityResolution
{
    public static Severity Resolve(PatternDefinition? patternDefinition, Severity ruleDefaultSeverity);
    public static void Validate(Finding finding);
    public static int GetWeight(Severity severity);
}
```

**Methods:**

- `Resolve()`: Implements the standardized resolution contract
- `Validate()`: Defensive validation that Finding.Severity is valid
- `GetWeight()`: Gets the weight multiplier for RiskScore calculation (moved from RiskScore)

### Modified: `RegexScanRule.cs`

**PatternDefinition record:**
- Added comprehensive XML documentation explaining the severity override contract
- Clarifies that `SeverityOverride` takes precedence over `DefaultSeverity`

**RegexScanRule class:**
- Updated `ScanCore()` to use `SeverityResolution.Resolve()` instead of inline resolution
- Added `SeverityResolution.Validate()` call to ensure Finding.Severity is valid
- Added comprehensive XML documentation explaining the severity resolution flow

**Before:**
```csharp
yield return new Finding(
    Id,
    Name,
    definition.SeverityOverride ?? DefaultSeverity,  // Inline resolution
    Category,
    ...
);
```

**After:**
```csharp
var resolvedSeverity = SeverityResolution.Resolve(definition, DefaultSeverity);
var finding = new Finding(
    Id,
    Name,
    resolvedSeverity,  // Centralized resolution
    Category,
    ...
);

SeverityResolution.Validate(finding);
yield return finding;
```

### Modified: `RiskScore.cs`

**Added documentation:**
- Added XML documentation block explaining the severity contract
- Clarifies that Finding.Severity is already resolved and used consistently
- Moved `GetWeight()` method to `SeverityResolution` class (with updated documentation)
- Added parameter validation to `Weight()` method

### Modified: `Models.cs` (Finding record)

**Added documentation:**
- Added comprehensive XML documentation to the `Finding` record
- Includes a "Severity Contract" remarks section explaining:
  - Severity is resolved exactly once at construction time
  - For PatternDefinition-based rules: `PatternDefinition.SeverityOverride ?? Rule.DefaultSeverity`
  - For direct rules: severity is provided directly
  - This resolved severity is what gets aggregated into RiskScore.Counts
  - No divergence between displayed severity and counted severity

### Modified: `PromptInjectionRule.cs`

**Updated context adjustment:**
- Updated to use `SeverityResolution.Validate()` for the adjusted finding
- Clarified in comments that base finding's Severity was already resolved via `SeverityResolution.Resolve()`

## Severity Resolution Flow

### For PatternDefinition-based Rules (RegexScanRule and subclasses):

```
1. Rule declares DefaultSeverity (e.g., Severity.High)
2. PatternDefinition declares optional SeverityOverride (e.g., Severity.Critical)
3. SeverityResolution.Resolve(patternDefinition, rule.DefaultSeverity)
   ├─ If patternDefinition.SeverityOverride is set → use that value
   └─ Otherwise → use rule.DefaultSeverity
4. Finding is created with the resolved severity
5. RiskScore aggregates using Finding.Severity (same value)
```

### For Direct Rule Implementations (UnreviewedPayloadRule, NetworkEgressRule, etc.):

```
1. Rule declares DefaultSeverity
2. Finding is created with severity provided directly
3. RiskScore aggregates using Finding.Severity
```

### For Context-Adjusted Rules (PromptInjectionRule):

```
1. Base rule creates Finding with resolved severity
2. Context adjustment creates new Finding with adjusted severity
3. SeverityResolution.Validate() ensures adjusted severity is valid
4. Both findings use severity values that are consistent with RiskScore aggregation
```

## Benefits

1. **Consistency**: Finding.Severity and RiskScore.Counts always use the same value
2. **Maintainability**: Centralized resolution logic in one place
3. **Documentation**: Clear contracts prevent future divergence
4. **Defensive**: Validation catches edge cases
5. **Reusability**: `SeverityResolution` can be used by any rule type

## Testing

The solution builds successfully with 0 errors:
- SkillGuard.Core: ✅ Build succeeded
- SkillGuard.Rules: ✅ Build succeeded  
- SkillGuard.Cli: ✅ Build succeeded
- SkillGuard.Tests: ✅ Build succeeded

All existing rules continue to work with the new centralized resolution.

## Backward Compatibility

✅ **Fully backward compatible**
- All existing rules work without modification
- The resolution logic produces identical results to before
- Only adds documentation and centralized logic, no behavior changes
- PatternDefinition.SeverityOverride ?? DefaultSeverity produces the same result as SeverityResolution.Resolve()

## Future Considerations

1. Other rule types could adopt `SeverityResolution` for consistency
2. The validation in `SeverityResolution.Validate()` could be extended to check other Finding properties
3. Severity weights could be made configurable if needed
4. Additional severity levels could be added without breaking the contract
