import json
import time
from pathlib import Path

from repair_workspace import run_command


DEFAULT_PROVIDER = "claude"
DEFAULT_CLAUDE_MODEL = "claude-opus-4-8"


def resolve_model(provider, model):
    if model is None and provider == "claude":
        return DEFAULT_CLAUDE_MODEL
    return model


REPAIR_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "edits": {
            "type": "array",
            "minItems": 1,
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


def validate_output(value, schema, path="root"):
    """Validate the object/array/string subset used by our repair and plan schemas."""
    kind = schema.get("type")
    expected = {"object": dict, "array": list, "string": str}
    if kind in expected and not isinstance(value, expected[kind]):
        raise ValueError(f"{path}: expected {kind}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path}: expected one of {schema['enum']}")
    if kind == "object":
        for key in schema.get("required", []):
            if key not in value:
                raise ValueError(f"{path}: missing required property '{key}'")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                raise ValueError(f"{path}: unexpected properties {sorted(extra)}")
        for key, item in value.items():
            if key in properties:
                validate_output(item, properties[key], f"{path}.{key}")
    if kind == "array":
        if len(value) < schema.get("minItems", 0):
            raise ValueError(f"{path}: must contain at least {schema['minItems']} item(s)")
        for index, item in enumerate(value):
            validate_output(item, schema.get("items", {}), f"{path}[{index}]")


def parse_json_reply(raw):
    if not isinstance(raw, str):
        raise ValueError("Claude result must contain JSON text")
    text = raw.strip()
    # Accept one enclosing Markdown fence, but never extract fragments or unescape
    # source strings a second time: that would corrupt Java literals and regexes.
    lines = text.splitlines()
    if len(lines) >= 3 and lines[0] in ("```json", "```") and lines[-1] == "```":
        text = "\n".join(lines[1:-1])
    return json.loads(text)


class RepairAgent:
    def __init__(self, provider, model=None):
        self.provider = provider
        self.model = resolve_model(provider, model)

    def generate(self, prompt, folder, timeout, schema_definition=None):
        folder = Path(folder)
        folder.mkdir()
        schema = folder / "schema.json"
        schema_definition = schema_definition or REPAIR_SCHEMA
        schema.write_text(json.dumps(schema_definition), encoding="utf-8")
        reply = folder / "reply.json"
        if self.provider == "codex":
            command = ["codex", "exec", "--sandbox", "read-only", "--ephemeral", "--json",
                       "--skip-git-repo-check", "--output-schema", str(schema), "-o", str(reply)]
        elif self.provider == "claude":
            # Avoid Claude Code's StructuredOutput tool serialization/retry loop.
            # Keep the CLI JSON envelope (usage/errors); parse its text result locally.
            command = ["claude", "-p", "--output-format", "json", "--tools", "",
                       "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}',
                       "--setting-sources", "", "--no-session-persistence"]
            prompt += ("\n\nResponse contract: Return exactly one JSON object matching the schema below. "
                       "Every required root property must be at the top level, not embedded in summary. "
                       "Use native JSON arrays/objects, not stringified JSON or XML tool calls. "
                       "Encode source strings once as JSON: a source newline is a JSON newline escape; "
                       "preserve literal backslashes inside source code. No commentary or tool-call markup.\n"
                       + json.dumps(schema_definition))
        else:
            raise ValueError("Choose codex or claude")
        if self.model:
            command += ["--model", self.model]
        (folder / "prompt.txt").write_text(prompt, encoding="utf-8")
        deadline = time.monotonic() + timeout
        feedback = ""
        attempts = 3 if self.provider == "claude" else 1
        for attempt in range(1, attempts + 1):
            log = folder / ("agent.log" if attempt == 1 else f"agent-{attempt}.log")
            request = prompt + feedback
            if attempt > 1:
                (folder / f"prompt-{attempt}.txt").write_text(request, encoding="utf-8")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"Agent failed: timed out; see {log}")
            result = run_command(command, folder, remaining, log, request)
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
                    if isinstance(event, dict) and event.get("is_error"):
                        detail = str(event.get("errors") or event.get("result") or detail)[:2000]
                raise RuntimeError(f"Agent failed: {detail}; see {log}")
            try:
                if self.provider == "claude":
                    response = json.loads(result["output"])
                    if not isinstance(response, dict):
                        raise ValueError("Claude CLI envelope must be an object")
                    if response.get("is_error"):
                        raise RuntimeError(f"Agent failed: {response.get('errors') or response.get('result')}; see {log}")
                    proposal = parse_json_reply(response.get("result"))
                else:
                    proposal = json.loads(reply.read_text(encoding="utf-8"))
                validate_output(proposal, schema_definition)
            except ValueError as error:
                (folder / f"validation-{attempt}.txt").write_text(str(error), encoding="utf-8")
                if attempt == attempts:
                    raise ValueError(f"Invalid agent JSON after {attempt} attempt(s): {error}; see {log}") from error
                feedback = ("\n\nYour previous response failed local validation: " + str(error)
                            + ". Return the complete corrected object, including every required top-level property. "
                            "Do not return only a summary or only the corrected field.")
                continue
            reply.write_text(json.dumps(proposal, indent=2), encoding="utf-8")
            return proposal
