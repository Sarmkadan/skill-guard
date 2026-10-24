---
name: Bug report
about: Report a problem with skill-guard scanning, reporting, or the CLI
title: "[Bug]: "
labels: ["bug", "needs-triage"]
---

## Description

A clear and concise description of what the bug is.

## Steps to reproduce

1. Command or action you ran (for example `skill-guard scan <path> --fail-on high`)
2. Input used (a minimal skill file or directory that triggers the issue; remove any real secrets)
3. Observe the result

## Expected behavior

What you expected skill-guard to do.

## Actual behavior

What skill-guard actually did, including the console, JSON, or SARIF output if relevant.

## Environment

- skill-guard version: <!-- `skill-guard --version` or the tag/commit you built from -->
- .NET SDK / runtime version: <!-- `dotnet --version` -->
- Operating system and version: <!-- for example Ubuntu 24.04, Windows 11 23H2, macOS 15.2 -->
- Install method: <!-- dotnet tool install -g skill-guard / built from source / GitHub Action -->
- Output format and flags used: <!-- console / json / sarif, --fail-on, --disable, --allow-host, etc. -->

## Logs

<details>
<summary>Logs and output</summary>

```text
Paste the relevant console output, exception stack trace, or SARIF/JSON excerpt here.
```

</details>

## Additional context

Anything else that helps, such as the rule ID (SGnnn) involved, a false positive or false negative, or related issues.
