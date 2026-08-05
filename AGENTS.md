# Agents

This repository contains a set of **agent skill files** that are scanned by **skill‑guard**.  
Agent skill files are Markdown documents that describe the behavior of AI agents,
including prompts, tool usage, and embedded scripts. The scanner looks for security
issues such as prompt injection, credential leakage, unsafe shell commands, and
network egress to disallowed hosts.

## What to include

- **Skill definitions** (`.claude/skills/**`): Markdown files that define the
  instructions an agent should follow.
- **Agent definitions** (`.claude/agents/**`): Markdown files that configure the
  agent’s persona, system prompts, and tool bindings.
- **Supporting files** such as `AGENTS.md` (this file), `CLAUDE.md`,
  `.cursor/rules/**`, `.mdc` files, `mcp.json` manifests, and any bundled shell
  scripts.

## How skill‑guard uses this file

`skill‑guard` scans the repository for the patterns listed above. When it finds
issues, it reports them with a SARIF output that can be consumed by GitHub Code
Scanning or other CI tools. The presence of this `AGENTS.md` file signals that
the repository contains agent‑related assets and should be included in security
audits.

## Contributing

When adding new agent or skill files:

1. Place them under the appropriate directory (`.claude/skills/` or
   `.claude/agents/`).
2. Run `skill‑guard scan .` locally to verify that no new findings are introduced.
3. If a finding is legitimate, consider adding a **suggested fix** or updating the
   rule configuration (e.g., allow‑listing a host).

For more details on the available rules and their severities, see the
`README.md` under the **Rules** section.  

---  

*This file is intentionally kept lightweight; the bulk of the documentation lives
in the main README and the rule‑specific test suites.*  
