# skill-guard

Static security scanner (.NET 10 CLI tool) for agent skill/instruction files: flags prompt injection, credential exfiltration, dangerous shell, network egress, MCP misconfiguration. Outputs console, JSON or SARIF 2.1.0.

## Build

```
dotnet restore
dotnet build --configuration Release --no-restore
dotnet pack src/SkillGuard.Cli/SkillGuard.Cli.csproj --configuration Release --no-build --output artifacts
```

Run locally: `dotnet run --project src/SkillGuard.Cli -- scan samples --fix` or `... -- rules`.

## Test

```
dotnet test                                   # all (xunit)
dotnet test --filter "FullyQualifiedName~RuleTests"
```

Tests live in `tests/SkillGuard.Tests`; `Corpus/KnownBad/` holds sample malicious files used by engine tests. CI (`.github/workflows/ci.yml`) runs restore, build, test, pack on push to `master` and on PRs.

## Lint / format

No `.editorconfig` or analyzers configured. `Nullable` and `ImplicitUsings` are enabled in every project; treat nullable warnings as real. `dotnet format` is the only formatter.

## Layout

- `SkillGuard.slnx` - solution (XML format).
- `src/SkillGuard.Cli/` - entry point. `Program.cs` defines `scan` and `rules` commands via System.CommandLine; `ScanRunner.Run(...)` does discovery, scanning, reporting and returns the exit code.
- `src/SkillGuard.Core/` - engine and contracts: `Interfaces.cs` (`IScanRule`, `IScanner`, `IReporter`, `IFileDiscovery`, `ISuggestsFix`), `Models.cs` (`Finding`, `Severity`, `ScanTarget`, `ScanReport`), `RegexScanRule.cs` (base class + `PatternDefinition`), `RuleEngine.cs`, `FileDiscovery.cs` / `GitDiffFileDiscovery.cs`, `SkillFileClassifier.cs`, `RiskScore.cs`, `SeverityResolution.cs`, `FixSuggester.cs`, reporters (`ConsoleReporter`, `JsonReporter`, `SarifReporter`).
- `src/SkillGuard.Rules/` - one file per rule (SG001-SG011); `RuleCatalog.CreateDefaultRules()` is the single registration point.
- `tests/SkillGuard.Tests/` - xunit tests, one `*Tests.cs` per rule/component.
- `samples/` - demo scan target referenced by the README.
- `action.yml` - composite GitHub Action wrapping `dotnet tool install -g skill-guard`.
- Stray artifacts to ignore: `TestFixIntegration/`, `*.csx`, `buildcmd.py`, `src/SkillGuard/BuildCmd.py`, `*_SUMMARY.md`, `main()`.

## Conventions

- Rules: `public sealed class XxxRule : RegexScanRule` (optionally `, ISuggestsFix`), overriding `Id` (`SGnnn`), `Name`, `Description`, `DefaultSeverity`, `Category`, `Remediation`, and `Patterns` as a collection expression of `PatternDefinition(Regex, message, Severity? override)`. Regexes use `RegexOptions.Compiled`. Register new rules in `RuleCatalog` and document them in the README rules table.
- Severity: per-pattern `SeverityOverride` wins over the rule default; resolved once in the `Finding` constructor and reused by `RiskScore` (weights CRITICAL 40 / HIGH 15 / MEDIUM 5 / LOW 1, grade A-F).
- `--fix` is advisory only; the tool never edits scanned files.
- Interfaces in `I*.cs`, models as records/sealed classes, `namespace X;` file-scoped, C# `latest` with collection expressions.
- Tests: xunit `[Fact]`/`[Theory]`, named `Fires_On...` / `StaysSilent_On...` for rule positive/negative cases.
- Exit code is non-zero when a finding reaches `--fail-on` (default `high`).
