import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from repair_agent import DEFAULT_PROVIDER, resolve_model
from repair_main import run_repair
from repair_workspace import run_command

STATUSES = ["validated", "rejected", "inconclusive", "prepared", "error"]


def discover(scenarios):
    paths = []
    for entry in scenarios:
        path = Path(entry)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.json")))
        else:
            paths.append(path)
    return paths


def _execute(scenario, folder, provider, model, prepare_only, proposal, corpus):
    row = {"scenario": str(scenario), "output": str(folder)}
    try:
        report = run_repair(str(scenario), folder, provider, model, prepare_only, proposal, corpus)
        row.update({"id": report["id"], "status": report["status"], "cwe": report["cwe"],
                    "repository": report["repository"], "vcc": report["vcc"],
                    "accepted_attempt": report.get("accepted_attempt"), "reason": report.get("reason")})
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        row.update({"status": "error", "reason": str(error)})
    return row


def _summarize(output, runs, provider, model):
    summary = {"generated_utc": datetime.now(timezone.utc).isoformat(), "provider": provider,
               "model": model, "total": len(runs),
               "counts": {status: sum(r["status"] == status for r in runs) for status in STATUSES},
               "runs": runs}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def run_batch(scenarios, output, provider=DEFAULT_PROVIDER, model=None, corpus=None, prepare_only=False):
    model = resolve_model(provider, model)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    runs = []
    for index, scenario in enumerate(discover(scenarios), start=1):
        folder = output / f"{index:03d}_{scenario.stem}"
        logging.info("Scenario %s -> %s", scenario, folder)
        runs.append(_execute(scenario, folder, provider, model, prepare_only, None, corpus))
    return _summarize(output, runs, provider, model)


def build_scenario(case, work):
    """Resolve a case to a scenario path, running its setup command when given."""
    if case.get("scenario"):
        return Path(case["scenario"]).resolve()
    setup = case.get("setup")
    if not isinstance(setup, list) or not setup or not all(isinstance(x, str) for x in setup):
        raise ValueError("Each case needs a scenario path or a setup command list")
    command = [part.replace("{work}", str(work)) for part in setup]
    result = run_command(command, Path.cwd(), case.get("setup_timeout", 1800), work.parent / "setup.log")
    if result["timed_out"] or result["returncode"] != 0:
        raise RuntimeError(f"Setup failed; see {work.parent / 'setup.log'}")
    lines = [line for line in result["output"].splitlines() if line.strip()]
    if not lines:
        raise ValueError("Setup produced no scenario path")
    return Path(lines[-1].strip()).resolve()


def run_manifest(manifest, output, provider=DEFAULT_PROVIDER, model=None, prepare_only=False):
    model = resolve_model(provider, model)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    cases = json.loads(Path(manifest).read_text(encoding="utf-8")).get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("The manifest must contain a non-empty cases list")
    runs = []
    for index, case in enumerate(cases, start=1):
        identifier = case.get("id", f"case{index}")
        folder = output / f"{index:03d}_{identifier}"
        folder.mkdir(parents=True)
        row = {"id": identifier, "output": str(folder)}
        try:
            scenario = build_scenario(case, folder / "work")
            report = run_repair(str(scenario), folder / "repair", provider, model, prepare_only,
                                case.get("proposal"), case.get("corpus"))
            row.update({"status": report["status"], "cwe": report.get("cwe"), "scenario": str(scenario),
                        "repository": report.get("repository"), "vcc": report.get("vcc"),
                        "accepted_attempt": report.get("accepted_attempt"), "reason": report.get("reason")})
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            row.update({"status": "error", "reason": str(error)})
        logging.info("Case %s -> %s", identifier, row["status"])
        runs.append(row)
    return _summarize(output, runs, provider, model)


def main():
    parser = argparse.ArgumentParser(description="Run repair scenarios reproducibly and summarize outcomes")
    parser.add_argument("scenarios", nargs="*", help="Scenario JSON files or directories of them")
    parser.add_argument("--manifest", help="JSON manifest of cases that each build and run a scenario")
    parser.add_argument("--output", required=True)
    parser.add_argument("--provider", choices=["codex", "claude"], default=DEFAULT_PROVIDER)
    parser.add_argument("--model", help="Model override (Claude default: claude-opus-4-8; Codex: CLI default)")
    parser.add_argument("--corpus")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if args.manifest:
        summary = run_manifest(args.manifest, args.output, args.provider, args.model, args.prepare_only)
    elif args.scenarios:
        summary = run_batch(args.scenarios, args.output, args.provider, args.model, args.corpus, args.prepare_only)
    else:
        parser.error("Provide scenario paths or --manifest")
    print(json.dumps({key: summary[key] for key in ["total", "counts"]}, indent=2))
    return 0 if summary["counts"]["error"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
