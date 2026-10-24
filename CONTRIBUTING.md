# Contributing to skill-guard

Thanks for helping. skill-guard is a static scanner for agent skill and instruction files, so changes to rules are security-sensitive; keep them small, tested and easy to review.

## Prerequisites

- **.NET 10 SDK** (`10.0.x`; CI uses `actions/setup-dotnet` with `10.0.x`). There is no `global.json`, so any 10.0 SDK works.
- Git.

Check your setup with `dotnet --version`.

## Build

From the repository root:

```bash
dotnet restore SkillGuard.slnx
dotnet build SkillGuard.slnx --configuration Release --no-restore
```

To run the scanner from source:

```bash
dotnet run --project src/SkillGuard.Cli -- scan samples
dotnet run --project src/SkillGuard.Cli -- rules
```

## Run tests

```bash
dotnet test SkillGuard.slnx
```

To run a subset, for example one rule's tests:

```bash
dotnet test --filter "FullyQualifiedName~RuleTests"
```

Tests use xunit and live in `tests/SkillGuard.Tests/`, one `*Tests.cs` file per rule or component. Sample malicious files used by engine tests are in `tests/SkillGuard.Tests/Corpus/`.

## Code style

- There is no `.editorconfig` and no analyzers. Run `dotnet format` before committing; it is the only formatter in use.
- Nullable reference types and implicit usings are enabled in every project. Treat nullable warnings as real and do not suppress them without a reason.
- Use file-scoped namespaces (`namespace X;`), C# `latest`, and collection expressions.
- Interfaces go in `I*.cs` files; models are records or sealed classes.
- Match the surrounding code: naming, comment density and idiom.

### Adding or changing a rule

- One rule per file in `src/SkillGuard.Rules/`: `public sealed class XxxRule : RegexScanRule`, overriding `Id`, `Name`, `Description`, `DefaultSeverity`, `Category`, `Remediation` and `Patterns`. Compile regexes with `RegexOptions.Compiled`.
- Register new rules in `RuleCatalog.CreateDefaultRules()` and add a row to the rules table in `README.md`.
- Add positive and negative tests. Name them `Fires_On...` and `StaysSilent_On...`.
- `--fix` suggestions are advisory only. The tool must never edit scanned files.

## Branch naming

Branch from `master` and use the same type prefix as the commit subject:

- `feat/<short-description>`
- `fix/<short-description>`
- `test/<short-description>`
- `refactor/<short-description>`
- `docs/<short-description>`

Example: `fix/sg005-ipv6-allowlist`.

## Commits

Use Conventional Commit subjects, for example `fix: resolve false positive in SG005 allowlist`.

## Pull requests

1. Keep PRs small and focused on one change. Split refactors from behaviour changes.
2. Include tests for every behaviour change. Rule changes need both a firing and a silent case.
3. Make sure `dotnet build` and `dotnet test` pass locally.
4. CI must pass before merge. The `ci` workflow (`.github/workflows/ci.yml`) runs restore, build, test and pack on pushes and PRs to `master`.
5. Update `README.md` when you add a rule, change a default severity, or change CLI behaviour.
6. Do not commit build output (`bin/`, `obj/`) or stray local artifacts.

Describe what changed and why in the PR body, and call out any change to severity or scoring, since those affect users' exit codes.
