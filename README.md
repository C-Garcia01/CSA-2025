# RAG-VCC

RAG-VCC is a research project from the University of Notre Dame Computing Skills Accelerator Program. It uses retrieval-augmented generation (RAG) to work with vulnerable code and build datasets of code changes. RAG means giving the model relevant examples alongside the code it needs to change.

This version of the project focuses on **repairing vulnerable snapshots and saving the original and generated versions as Git commits**. The CSV output connects each code pair to its CWE category, commit hashes, and generation results. This makes it possible to inspect what the model actually changed instead of only reading its explanation.

The repository also contains the original pipeline, which introduces vulnerabilities into safe code. That is a separate workflow with different dependencies. The instructions below start with the repair pipeline.

## Contents

- [What the project does](#what-the-project-does)
- [Setup](#setup)
- [Run Juliet from a local ZIP](#run-juliet-from-a-local-zip)
- [How the repair pipeline works](#how-the-repair-pipeline-works)
- [Read the results](#read-the-results)
- [Run with behavioral validation](#run-with-behavioral-validation)
- [Other ways to run repairs](#other-ways-to-run-repairs)
- [Repository layout](#repository-layout)
- [Tests and troubleshooting](#tests-and-troubleshooting)
- [Original vulnerability-generation pipeline](#original-vulnerability-generation-pipeline)

## What the project does

The repair pipeline takes a vulnerable input, retrieves relevant repair examples, asks a model to propose source edits, and saves the outcome. There are two ways to use it:

| Workflow | Entry point | What it produces |
| --- | --- | --- |
| Direct Juliet repair | `src/repair_juliet.py` | Generated repairs, original/repair Git histories, and CSV exports. No generated test harness or behavioral validation. |
| Repair with behavioral checks | `src/repair_juliet.py --validate` or `src/repair_main.py` | Repairs checked against a build, functional tests, and a security probe. A commit URL also triggers a separate model call to prepare the checks. |

A **CWE** identifies a type of weakness, such as CWE-89 for SQL injection. A **VCC** is a vulnerability-contributing commit. For Juliet, the input commits are synthetic snapshots imported from the dataset; they are not historical commits that introduced vulnerabilities into real projects.

The default provider is the **Claude Code CLI**, using **Claude Opus 4.8** (`claude-opus-4-8`). The runner uses the CLI's existing authentication, including a Claude subscription login.

A generated repair is not automatically a correct repair. Direct-mode results are labeled `generated_unvalidated`. Even a `validated` result only means the configured checks passed; it does not establish that the entire application is secure.

## Setup

Run the commands in this README from the repository root.

For direct repair, the requirements are Python 3.10 or newer, Git, and an authenticated Claude Code CLI. The repair scripts use Python's standard library. They do not need the original pipeline's GPU, Ollama, LangChain, or embedding setup.

Check the tools and sign in:

```bash
python --version
git --version
claude --version
claude auth login
claude auth status
```

If your system names Python 3 `python3`, use that in place of `python`. Claude calls use the authenticated account's available usage and limits. The runner does not require an API key for the subscription-based setup used in this project.

For Java **validation**, also put a suitable JDK on `PATH`. The Juliet pilot used Java 8. Maven is needed for examples that use Maven, including the Java demo and SkyWalking case. Direct mode reads and edits Java source without compiling it, so it does not require a JDK just to generate repairs.

```bash
java -version
javac -version
# For Maven-based validation cases:
mvn -version
```

To use another model, pass `--model MODEL`. To use the Codex CLI instead, pass `--provider codex`; without a model override, it uses its configured default.

## Run Juliet from a local ZIP

Once Python, Git, and Claude Code are installed and Claude is signed in, **you can run the experiment with one command**. Run it from this repository's root and pass the path to your Juliet Java 1.3 ZIP. The program handles extraction, RAG retrieval, model calls, Git commits, and CSV export.

### Small test: one case from each supported CWE

```bash
python src/repair_juliet.py juliet.zip
```

Replace `juliet.zip` with your archive's filename or full path. For example:

```bash
python src/repair_juliet.py "$HOME/Downloads/2017-10-01-juliet-test-suite-for-java-v1-3.zip"
```

This runs the same **10-CWE pilot** used for the published results. There is no need to unpack the ZIP, create scenarios, set environment variables, or run a separate preparation command.

### Larger run: every case in the supported CWEs

```bash
python src/repair_juliet.py juliet.zip --per-cwe 0
```

`--per-cwe 0` removes the one-case-per-CWE limit. It processes every case that the current adapter supports in the archive.

**Scope:** the adapter currently supports CWE-15, 78, 80, 81, 83, 89, 113, 129, 134, and 606. Passing the full Juliet ZIP does not include other CWE categories or the C/C++ suite. Processing every Java CWE would require extending the adapter. The larger run makes thousands of model calls sequentially and is subject to your Claude account's usage limits.

Both commands use **Claude Opus 4.8**, the existing Claude CLI login, and `data/splits/rag/repairs.jsonl` automatically. They generate repairs directly, without a separate test-harness call. Results are labeled `generated_unvalidated` because this mode does not run behavioral security tests.

### Where to find the results

The program prints its output directory at startup, for example `data/runs/juliet-.../`. Open:

- **`results.csv`** for every selected case, its status, and the original/repair commit hashes.
- **`pairs.csv`** for cases that produced changed-file pairs.
- **`summary.json`** for counts and failure reasons.

The CSVs update as cases finish. Original commits, generated repairs, prompts, and logs are saved under the same run directory. A blank repair hash means that case has not produced a repair. See [Read the results](#read-the-results) for the full output reference.

### Resume a stopped run

Use the same ZIP and the actual output directory printed by the earlier command:

```bash
python src/repair_juliet.py juliet.zip --output data/runs/YOUR_RUN --resume
```

Replace `YOUR_RUN` with the existing folder name. The runner remembers which cases were selected, so a full run stays a full run when resumed. Add `--retry-failed` to retry unsuccessful cases as well:

```bash
python src/repair_juliet.py juliet.zip --output data/runs/YOUR_RUN --resume --retry-failed
```

Completed successful cases are kept, and earlier failure evidence is preserved. If you changed the provider, model, corpus, or validation mode for the first run, repeat those options when resuming.

### Optional settings

These are optional; the one-line commands above are enough for the normal experiment.

| Option | When to use it |
| --- | --- |
| `--per-cwe 5` | Run up to five cases per supported CWE. The default is one; `0` means all. |
| `--output data/runs/my-run` | Pick a new output directory instead of using an automatically named one. |
| `--prepare-only` | Import the input commits and CSV inventory without calling Claude. Resume later to generate repairs. |
| `--validate` | Add the slower harness-generation and behavioral-check workflow. Requires the appropriate build tools; see [validation](#run-with-behavioral-validation). |
| `--model MODEL` | Override Opus 4.8. |
| `--provider codex` | Use the Codex CLI instead of Claude Code. |
| `--corpus PATH` | Use a different reviewed repair-example corpus. |

Use the original Juliet Java ZIP, which contains `Java/src/testcases/`, `Java/src/testcasesupport/`, and `Java/lib/`. An extracted folder or a different dataset format needs an adapter; it cannot be passed to this command directly.

A fresh run repeats the experiment, but model output and commit timestamps can differ. For the exact code and hashes from the published pilot, use the [results repository](https://github.com/C-Garcia01/juliet-java-rag-repair-results). The runner records the archive fingerprint and run settings automatically.

## How the repair pipeline works

### 1. Build the vulnerable input

The Juliet adapter groups files belonging to the same testcase. It removes supplied good implementations and testcase comments so the model is not handed the reference repair. Empty `good()` stubs remain where the original class structure requires them. Runtime support files, bundled dependencies, and their notices are retained.

The adapter commits this input to a new Git repository. That commit becomes `before_commit`. The original ZIP is unchanged, and its SHA-256 fingerprint is recorded for reproducibility.

### 2. Retrieve repair examples

The default corpus is `data/splits/rag/repairs.jsonl`. Retrieval selects records marked `reviewed: true` in the RAG split, requires an exact CWE match, and excludes the target repository, shared case group, explicit exclusions, and duplicate before/after snippets.

Eligible examples are ranked by word/token overlap with the weakness description. This is a lightweight lexical retrieval baseline. The repair workflow does not use the original generation pipeline's vector embeddings.

Direct Juliet repair includes up to two retrieved examples, along with the testcase source and runtime support. If no eligible examples exist, the model receives source context alone. The prompt's actual example IDs are saved in `retrieved_examples`. New generated repairs are not automatically added to the reviewed corpus.

### 3. Ask the model for edits

The prompt asks the model to repair the unsafe behavior while keeping legitimate functionality. Claude runs with tools disabled and returns a JSON object containing a `summary` and an `edits` array. Each edit has three fields:

| Field | Meaning |
| --- | --- |
| `path` | An allowed source file to change. |
| `old` | Existing text that must occur exactly once. |
| `new` | Replacement text. |

The runner parses Claude's text response and validates the JSON locally. Missing fields, wrong types, or an empty edit list are rejected. Format retries include the specific validation error, and every attempt is logged. Source strings are decoded once so JSON handling does not rewrite code escapes.

### 4. Apply and commit the repair

The runner creates an isolated checkout of the original commit. It checks every edit before writing changes, rejects paths outside the allowed source files, and requires each `old` string to match exactly once.

In direct mode, a changed result is committed immediately and marked `generated_unvalidated`. The new commit becomes `after_commit`, with the original commit as its parent. The pipeline saves the patch, hashes, model response, and Git history. It does not automatically push anything to GitHub.

The separate validation workflow adds checks before accepting a repair, as described below.

## Read the results

A Juliet run writes these files at the top of its output directory:

| File | Contents |
| --- | --- |
| `results.csv` | Outcomes for every selected case. Successful cases have rows for changed files; unsuccessful cases retain their status and reason. |
| `pairs.csv` | Generated or validated changed-file pairs only. Check the `status` column before using them. |
| `pairs.jsonl` | The paired source code and metadata, with one JSON object per line. |
| `summary.json` | Run configuration, case states, counts, and retry history. |
| `inputs/` | Original vulnerable repositories and import metadata. |
| `runs/` | Initial per-case repair runs and evidence. |
| `retries/` | Additional attempts created with `--retry-failed`. |

Direct per-case runs include `context.json`, `proposal.json`, `repair.patch`, `result.json`, the working repository, and an `agent/` folder containing prompts and responses. Successful runs also include `history.bundle`, which preserves the Git history in a portable file. Validation runs have additional preparation and check artifacts.

The main CSV fields are:

| Column | Meaning |
| --- | --- |
| `case_id`, `cwe` | The testcase and its weakness category. |
| `status` | The generation or validation outcome. |
| `before_commit`, `after_commit` | Git commit hashes for the vulnerable input and generated repair. |
| `prepared_revision` | An intermediate harness commit in validation mode; blank in direct mode. |
| `path` | The affected source file within the case repository. |
| `before_sha256`, `after_sha256` | SHA-256 fingerprints of that file's contents at the two commits. These are not Git commit hashes. |
| `provider`, `model` | The CLI provider and model used for generation. |
| `retrieved_examples` | A JSON array of example IDs included in the prompt; `[]` means none. |
| `historical_vcc` | `False` for imported Juliet snapshots. |
| `review_status`, `validation_scope` | Whether the output was independently reviewed and what validation was performed. |
| `reason`, `evidence` | A failure explanation, when applicable, and the path to the case report. |

The CSV does not embed the full source code. Use `pairs.jsonl` or the saved Git repositories for that. Failed or pending cases have blank repair hashes rather than placeholder commits.

Common statuses are:

| Status | Meaning |
| --- | --- |
| `pending` | A selected Juliet case has not completed generation. |
| `generated_unvalidated` | A repair was generated, applied, and committed without behavioral checks. |
| `validated` | The configured build, functional, and security checks passed. |
| `rejected` | A proposal was invalid or failed a validation check. |
| `inconclusive` | Generation, setup, baseline reproduction, or another required step could not complete. Read `reason`. |
| `prepared` | A scenario's context was exported without running the repair checks. Juliet's input-only preparation instead leaves cases `pending`. |
| `error` | The batch runner could not set up or execute a case. |

### Published pilot

The [public Juliet results repository](https://github.com/C-Garcia01/juliet-java-rag-repair-results) contains the 10-CWE pilot's exact original and repair histories, CSVs, patches, and reports. All 10 cases produced generated repairs after retrying three response-format failures. They remain behaviorally unvalidated.

Its [dataset column guide](https://github.com/C-Garcia01/juliet-java-rag-repair-results#dataset-column-definitions) defines every column, including the extra lookup URLs in `results-linked.csv`. Readers can verify the hashes with the included `verify_results.py` script. Recreating a commit can change its hash, so publishing a run requires preserving its existing Git objects, not just copying the files into a new commit.

## Run with behavioral validation

For Juliet, add `--validate` to a new run:

```bash
python src/repair_juliet.py \
  /path/to/2017-10-01-juliet-test-suite-for-java-v1-3.zip \
  --per-cwe 1 \
  --output data/runs/juliet-validated \
  --validate
```

This mode makes a separate model call to prepare a build/test harness before requesting a repair. It can take substantially longer than direct mode. Generated harness files are committed and protected from edits by the repair model.

The runner first builds the original code, runs functional tests, and checks that the security probe observes the weakness. It then applies a repair and repeats the checks. The security probe uses both an exit code and a marker:

| Observation | Exit code | Output marker |
| --- | --- | --- |
| Vulnerability reproduced | `1` | `VCC_SECURITY_FAIL` |
| Security assertion satisfied | `0` | `VCC_SECURITY_PASS` |
| Crash or setup failure | Failure as appropriate | Neither marker |

A functional test is meant to catch repairs that remove the feature instead of fixing it. These checks are only as useful as their coverage, and model-generated tests are not an independent review. Missing dependencies, external services, or a bad harness can leave a case inconclusive.

Build and test commands execute locally. For unfamiliar repositories, use a disposable container or VM; a cloned checkout is not an execution sandbox. The runner does not install arbitrary system packages or provision external services.

## Other ways to run repairs

### Repair a commit URL or local revision

```bash
python src/repair_main.py https://github.com/OWNER/REPO/commit/COMMIT_SHA
```

For a local Git repository:

```bash
python src/repair_main.py COMMIT_SHA --repository /path/to/repository
```

Replace the uppercase placeholders with real values. This entry point uses automatic preparation and behavioral validation. It inspects the pinned revision and its change, asks the model to prepare a scenario, and then attempts the repair. No handwritten scenario is required. The source repository stays unchanged.

Outputs default to a unique `data/runs/auto-.../` directory. The report keeps the input VCC, prepared harness revision, and final repair commit separate. Validated runs export commit pairs and a Git history bundle. See [REPAIR.md](REPAIR.md) for the detailed workflow and configuration format.

### Run the local demo without a model

The SQLite demo has a two-file SQL-injection flaw and a saved repair proposal. This checks the local pipeline without a Claude login or model call:

```bash
python examples/create_repair_demo.py /tmp/vcc-repair-demo
python src/repair_main.py /tmp/vcc-repair-demo/scenario.json \
  --output /tmp/vcc-repair-check \
  --proposal /tmp/vcc-repair-demo/proposal.json
```

Use fresh directories if those paths already exist. A successful run reports `"status": "validated"`. To ask Claude for a new repair, omit `--proposal` and choose a new output directory.

There is also a Maven/JDK 8 demo in [examples/create_java_repair_demo.py](examples/create_java_repair_demo.py) and a historical SkyWalking SQL-injection case with its own [instructions](examples/skywalking_cve_2020_13921/README.md).

### Run configured scenarios in a batch

```bash
python src/repair_batch.py data/scenarios \
  --output data/runs/scenario-batch \
  --corpus data/splits/rag/repairs.jsonl
```

`data/scenarios` is an example path: create your scenario JSON files there or substitute their actual directory. A scenario pins a repository revision, editable files, context, and build/test commands. The batch runner also accepts a manifest with per-case setup commands:

```bash
python src/repair_batch.py --manifest examples/real_vcc_batch.json \
  --output data/runs/batch-real
```

For scenario fields, corpus preparation, or drafting a scenario from a fixing commit, use [REPAIR.md](REPAIR.md).

## Repository layout

| Path | Role |
| --- | --- |
| `src/repair_juliet.py` | Imports Juliet cases, selects the pilot, manages resume/retry, and aggregates results. |
| `src/repair_direct.py` | Runs direct RAG repair and commits generated edits. |
| `src/repair_agent.py` | Calls Claude/Codex and validates model responses. |
| `src/repair_context.py` | Retrieves examples and builds repair prompts. |
| `src/repair_workspace.py` | Manages Git checkouts, applies edits, and runs validation commands. |
| `src/repair_main.py`, `src/repair_auto.py` | Run scenario-based or automatically prepared repairs. |
| `src/repair_batch.py` | Runs multiple configured scenarios. |
| `src/repair_scenario.py` | Drafts scenarios and inspects candidate VCC attribution. |
| `src/java_context.py` | Builds a bounded Java import/type inventory. |
| `data/splits/` | Separates RAG examples from development and test references. |
| `data/runs/` | Generated experiments; ignored by Git. |
| `examples/` | Demo projects, scenarios, and saved proposals. |
| `tests/` | Pipeline regression tests. |
| `src/main.py`, `GitHub-scrapers/`, `Trainers/` | Original generation, collection, and training code. |

## Tests and troubleshooting

Run the repair tests without making model calls:

```bash
python -m unittest discover -s tests -p 'test_repair*.py'
```

Run the complete test suite with:

```bash
python -m unittest discover -s tests -v
```

Tests use temporary Git repositories and mocked model responses. They check the pipeline's behavior, including JSON retries and exported hashes; they do not measure whether generated repairs are secure. The Java demo unit tests inspect the generated fixture without running Java; executing that scenario separately requires its JDK and Maven toolchain.

| Problem | What to check |
| --- | --- |
| CLI authentication or provider failure | Run `claude auth status`, check connectivity and account usage, then resume the Juliet run with `--retry-failed`. Provider failures stop the batch. |
| Invalid model JSON | Read `agent/validation-*.txt` and the corresponding response logs. Format retries are bounded, so persistent failures remain inconclusive. |
| Edit does not match the source | Read the proposal and case report. The runner requires one exact match and will not guess where to apply an edit. |
| Output directory already exists | Choose a fresh directory for a new run, or use Juliet's `--resume` for an existing one. |
| Missing Java, Maven, or service | Check the validation logs and the scenario's required environment. Direct Juliet generation does not run these checks. |
| No retrieved examples | Check the exact CWE, corpus path, and review/split filters. An empty match set is allowed and recorded. |
| Blank repair hash | Check `status` and `reason`; the case has not produced an exportable repair. |

`--prepare-only` has different behavior across entry points. Juliet only creates input commits and inventory. A supplied scenario exports its context without a model call. A commit URL/local SHA still calls the preparation model to construct a scenario, then skips the repair and validation stages.

## Original vulnerability-generation pipeline

The original code follows the opposite direction: it retrieves vulnerable examples and asks an Ollama-hosted model to introduce a weakness into safe input code. It uses LangChain, embeddings, Hugging Face tokenization, and GPU-oriented processing. Its entry point is `src/main.py`.

The main pieces are:

| Path | Role |
| --- | --- |
| `GitHub-scrapers/` | Collects source-file and commit-patch URLs. |
| `input-text/contextURLs.txt` | URLs used as retrieval context. |
| `input-text/inputLinks.txt` | Input files to transform. |
| `src/context_loader.py`, `src/vector_store.py` | Loads context and creates the vector store. |
| `src/qa_chain.py`, `src/process_commits.py` | Builds prompts and generates vulnerable code. |
| `src/GitHub_Commit.py` | Writes and pushes dataset commits. |
| `src/drive_upload.py` | Optional Google Drive upload support; the call is commented out in `main.py`. |

To work on this older workflow, configure its dependencies and Ollama model, copy `credentialsTemplate.json` to the ignored `credentials.json`, and fill in the input paths, tokens, and a dedicated dataset repository. Then run from the repository root:

```bash
python src/main.py
```

This is not a drop-in alternative to the repair command. The current code assumes four GPUs, and the environment snapshots and `runJob.sh` contain machine/cluster-specific settings that need adaptation. The legacy entry point clears the configured dataset repository's `files/` directory and pushes commits, so that repository must be a dedicated output checkout.

The original generated dataset is maintained separately at [CSA-2025-Dataset](https://github.com/mzampino1/CSA-2025-Dataset).
