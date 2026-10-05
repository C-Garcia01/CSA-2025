import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from repair_main import run_repair

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


def run_batch(scenarios, output, provider="codex", model=None, corpus=None, prepare_only=False):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    runs = []
    for index, scenario in enumerate(discover(scenarios), start=1):
        folder = output / f"{index:03d}_{scenario.stem}"
        logging.info("Scenario %s -> %s", scenario, folder)
        row = {"scenario": str(scenario), "output": str(folder)}
        try:
            report = run_repair(str(scenario), folder, provider, model, prepare_only, None, corpus)
            row.update({"id": report["id"], "status": report["status"], "cwe": report["cwe"],
                        "repository": report["repository"], "vcc": report["vcc"],
                        "accepted_attempt": report.get("accepted_attempt"),
                        "reason": report.get("reason")})
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            row.update({"status": "error", "reason": str(error)})
        runs.append(row)
    summary = {"generated_utc": datetime.now(timezone.utc).isoformat(), "provider": provider,
               "model": model, "total": len(runs),
               "counts": {status: sum(r["status"] == status for r in runs) for status in STATUSES},
               "runs": runs}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Run repair scenarios reproducibly and summarize outcomes")
    parser.add_argument("scenarios", nargs="+", help="Scenario JSON files or directories of them")
    parser.add_argument("--output", required=True)
    parser.add_argument("--provider", choices=["codex", "claude"], default="codex")
    parser.add_argument("--model")
    parser.add_argument("--corpus")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    summary = run_batch(args.scenarios, args.output, args.provider, args.model, args.corpus, args.prepare_only)
    print(json.dumps({key: summary[key] for key in ["total", "counts"]}, indent=2))
    return 0 if summary["counts"]["error"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
