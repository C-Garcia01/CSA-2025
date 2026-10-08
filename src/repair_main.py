import argparse
import hashlib
import json
import logging
import platform
from datetime import datetime, timezone
from pathlib import Path

from repair_agent import DEFAULT_PROVIDER, RepairAgent, resolve_model
from repair_context import RepairContext, make_prompt
from repair_workspace import RepairWorkspace, git_command, read_config


def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def run_repair(config_path, output, provider=DEFAULT_PROVIDER, model=None, prepare_only=False, proposal_path=None, corpus=None):
    model = resolve_model(provider, model)
    config = read_config(config_path)
    if corpus:
        config["corpus"] = str(Path(corpus).resolve())
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"id": config["id"], "status": "inconclusive", "cwe": config["cwe"],
              "repository": config["repository_id"], "vcc": config["revision"],
              "kind": "synthetic_repair", "environment": config["environment"],
              "python": platform.python_version(), "provider": provider, "model": model,
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "attempts": [], "review_status": "not_reviewed"}
    if proposal_path:
        report["provider"] = "supplied_proposal"
    try:
        save_json(output / "scenario.json", config)
        workspace = RepairWorkspace(output / "original")
        logging.info("Preparing %s at %s", config["repository_id"], config["revision"])
        submodules = bool(config.get("environment", {}).get("submodules"))
        workspace.prepare(config["repository"], config["revision"], submodules)
        report["parents"] = git_command(workspace.root, "show", "-s", "--format=%P", "HEAD").split()
        files = workspace.tracked_files()
        original_hashes = workspace.hashes(files)
        for name in config["editable_files"] + config["protected_files"]:
            if name not in original_hashes:
                raise ValueError(f"Configuration path is not tracked: {name}")
        bundle = RepairContext(config, workspace.root).build()
        save_json(output / "context.json", bundle)
        report["context_sha256"] = hashlib.sha256((output / "context.json").read_bytes()).hexdigest()
        report["corpus_sha256"] = hashlib.sha256(Path(config["corpus"]).read_bytes()).hexdigest()
        report["original_files_sha256"] = original_hashes
        report["retrieved_examples"] = [record["id"] for record in bundle["repair_examples"]]
        (output / "prompt.txt").write_text(make_prompt(bundle), encoding="utf-8")
        if prepare_only:
            report["status"] = "prepared"
            return report
        if not bundle["repair_examples"]:
            logging.info("No eligible repair examples; running with repository context only")

        logging.info("Checking the original vulnerability and functional baseline")
        baseline = RepairWorkspace(output / "baseline")
        baseline.prepare(str(workspace.root), config["revision"], submodules)
        result = baseline.validate(config, output / "baseline_checks", vulnerable=True)
        report["baseline"] = result
        if baseline.hashes(files) != original_hashes:
            raise ValueError("Baseline checks modified tracked files")
        if result["status"] != "passed":
            report["reason"] = "The original vulnerability was not established by the configured checks"
            return report

        agent = RepairAgent(provider, model)
        feedback = ""
        attempts = 1 if proposal_path else config["max_attempts"]
        for index in range(1, attempts + 1):
            logging.info("Repair attempt %s of %s", index, attempts)
            folder = output / f"attempt_{index}"
            folder.mkdir()
            attempt = {"number": index, "status": "rejected"}
            report["attempts"].append(attempt)
            try:
                if proposal_path:
                    proposal = json.loads(Path(proposal_path).read_text(encoding="utf-8"))
                else:
                    proposal = agent.generate(make_prompt(bundle, feedback), folder / "agent", config["agent_timeout"])
                save_json(folder / "proposal.json", proposal)
                candidate = RepairWorkspace(folder / "repository")
                candidate.prepare(str(workspace.root), config["revision"], submodules)
                patch = candidate.apply(proposal, config["editable_files"])
                if not patch.strip():
                    raise ValueError("Proposal made no changes")
                (folder / "repair.patch").write_text(patch, encoding="utf-8")
                before_checks = candidate.hashes(files)
                result = candidate.validate(config, folder / "checks", vulnerable=False)
                if candidate.hashes(files) != before_checks:
                    raise ValueError("Validation modified tracked files")
                if workspace.hashes(files) != original_hashes:
                    raise ValueError("Original checkout was modified")
                attempt.update(result)
                if result["status"] == "passed":
                    report["status"] = "validated"
                    report["accepted_attempt"] = index
                    report["patch_sha256"] = hashlib.sha256(patch.encode()).hexdigest()
                    report["repaired_files_sha256"] = before_checks
                    report["protected_files_sha256"] = workspace.hashes(config["protected_files"])
                    (output / "repair.patch").write_text(patch, encoding="utf-8")
                    return report
                feedback = result["reason"]
            except (ValueError, KeyError, TypeError) as error:
                attempt["reason"] = str(error)
                feedback = str(error)
        report["status"] = "inconclusive" if any(x["status"] == "inconclusive" for x in report["attempts"]) else "rejected"
        return report
    except (OSError, RuntimeError, ValueError) as error:
        report["reason"] = str(error)
        logging.error("Repair stopped: %s", error)
        return report
    finally:
        save_json(output / "result.json", report)


def main():
    parser = argparse.ArgumentParser(description="Repair a commit URL or local SHA; scenario JSON remains supported")
    parser.add_argument("target", help="GitHub commit URL, SHA in the current repo, or scenario JSON")
    parser.add_argument("--output", help="Optional output directory; otherwise a unique data/runs directory is created")
    parser.add_argument("--repository", help="Repository for a bare SHA (defaults to current directory)")
    parser.add_argument("--provider", choices=["codex", "claude"], default=DEFAULT_PROVIDER)
    parser.add_argument("--model", help="Model override (Claude default: claude-opus-4-8; Codex: CLI default)")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--proposal", help="Validate a saved JSON proposal without calling an agent")
    parser.add_argument("--corpus", help="Use a reviewed JSONL repair corpus instead of the scenario default")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        from repair_auto import output_path, run_auto
        destination = args.output or str(output_path())
        logging.info("Results: %s", Path(destination).resolve())
        if Path(args.target).is_file():
            report = run_repair(args.target, destination, args.provider, args.model,
                                args.prepare_only, args.proposal, args.corpus)
        else:
            if args.proposal:
                parser.error("--proposal is only supported for legacy scenario replay, not commit-only generation")
            report = run_auto(args.target, destination, args.provider, args.model,
                              args.corpus, args.repository, args.prepare_only)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))
    return 0 if report["status"] in ["prepared", "validated"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
