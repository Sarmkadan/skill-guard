# skill-guard

Static security scanner for agent skill and instruction files (`.claude/skills/**`, `AGENTS.md`, `.cursor/rules/**`, MCP manifests). Detects prompt injection, credential exfiltration, dangerous shell invocations, unexpected network egress, and unreviewed binary payloads. Ships as a dotnet tool and a GitHub Action.

```
dotnet tool install -g skill-guard
skill-guard scan . --format sarif --output results.sarif
```
