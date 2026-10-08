import json
from pathlib import Path

from repair_workspace import run_command


REPAIR_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "edits": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {key: {"type": "string"} for key in ["path", "old", "new"]},
                "required": ["path", "old", "new"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "edits"],
    "additionalProperties": False,
}


class RepairAgent:
    def __init__(self, provider, model=None):
        self.provider = provider
        self.model = model

    def generate(self, prompt, folder, timeout, schema_definition=None):
        folder = Path(folder)
        folder.mkdir()
        (folder / "prompt.txt").write_text(prompt, encoding="utf-8")
        schema = folder / "schema.json"
        schema_definition = schema_definition or REPAIR_SCHEMA
        schema.write_text(json.dumps(schema_definition), encoding="utf-8")
        reply = folder / "reply.json"
        if self.provider == "codex":
            command = ["codex", "exec", "--sandbox", "read-only", "--ephemeral", "--json",
                       "--skip-git-repo-check", "--output-schema", str(schema), "-o", str(reply)]
        elif self.provider == "claude":
            command = ["claude", "-p", "--output-format", "json", "--tools", "",
                       "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                       "--setting-sources", "", "--no-session-persistence",
                       "--json-schema", json.dumps(schema_definition)]
        else:
            raise ValueError("Choose codex or claude")
        if self.model:
            command += ["--model", self.model]
        result = run_command(command, folder, timeout, folder / "agent.log", prompt)
        if result["timed_out"] or result["returncode"] != 0:
            detail = "timed out" if result["timed_out"] else f"exit {result['returncode']}"
            for line in result.get("output", "").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and event.get("type") == "error" and isinstance(event.get("message"), str):
                    detail = event["message"][:2000]
                    break
            raise RuntimeError(f"Agent failed: {detail}; see {folder / 'agent.log'}")
        if self.provider == "claude":
            response = json.loads(result["output"])
            if response.get("is_error"):
                raise RuntimeError("Claude reported an unsuccessful run")
            proposal = response.get("structured_output")
        else:
            proposal = json.loads(reply.read_text(encoding="utf-8"))
        if not isinstance(proposal, dict) or not isinstance(proposal.get("summary"), str):
            raise ValueError("Agent did not return a structured repair")
        reply.write_text(json.dumps(proposal, indent=2), encoding="utf-8")
        return proposal
