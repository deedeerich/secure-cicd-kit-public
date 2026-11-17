# Fixtures for tests/prove_ai_artifact_inventory.py (KDEC-063)

`positive/` carries one of each risk the inventory flags; `negative/` carries the same artifact classes
written safely (exact versions, `${VAR}` references, narrow permissions, no hooks) and must produce no
finding.

Three things are NOT committed here and are written by the proof into a temporary copy instead:

- `claude-settings.json.fixture` is placed at `.claude/settings.json` in the copy. A real
  `.claude/settings.json` in this tree would be an agent control file of its own.
- `vscode-mcp.json.fixture` is placed at `.vscode/mcp.json` (the kit's `.gitignore` ignores `.vscode/`).
- hidden Unicode and secret-shaped strings are built from escapes at run time, so no invisible character
  or credential-shaped token sits in the kit's tracked source.
- the agent workflow is written at run time, so the kit's own workflow linters and pin checks never read
  a fixture workflow as one of the kit's.
