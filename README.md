# RAG-VCC

RAG-VCC (retrieval-augmented generation for vulnerability-contributing commits)
is a research project from the University of Notre Dame Computing Skills
Accelerator Program. It builds realistic, diverse training data for machine
learning models that detect vulnerable code.

The repository has two parts:

- **Generation pipeline** (original): injects vulnerable code into safe code
  with a large language model to synthesize vulnerability-contributing commits
  (VCCs). See [Generation pipeline](#generation-pipeline).
- **Repair workflow** (this fork): repairs a pinned vulnerable snapshot, proves
  the vulnerability before the repair and its absence afterward, and preserves
  the feature. It produces reviewed before-and-after pairs for the dataset. This
  page documents the repair workflow; [REPAIR.md](REPAIR.md) is the full
  reference.

All work targets old vulnerabilities that are already fixed upstream, for
defensive research.

## Repair workflow

### How it works

A *scenario* is a JSON file that pins one vulnerable snapshot and names the
files, build, and checks for one weakness. The runner turns a scenario into a
validated repair in five steps:

1. **Prepare.** Clone the repository and check out the pinned revision into a
   fresh, throwaway workspace. The source repository is never modified.
2. **Reproduce.** Build the snapshot, run the functional test, and run the
   security check. The security check must *fail* here, which proves the
   snapshot is vulnerable. If the build fails, the run is inconclusive.
3. **Retrieve.** Assemble a context bundle: the weakness description, the
   editable source files, and reviewed repair examples for the same Common
   Weakness Enumeration (CWE) category, drawn from a corpus.
4. **Generate.** Send the bundle to Codex CLI or Claude Code. The model returns
   JSON edits (`path`, `old`, `new`). The runner validates every edit, then
   applies them to a fresh checkout.
5. **Validate.** Rebuild and rerun all three checks. A repair is accepted only
   when the build and functional test pass *and* the security check now passes.

The security check reports the actual security property through a marker
contract, not just an exit code:

- Vulnerability reproduced: exit `1` and print `VCC_SECURITY_FAIL`.
- Vulnerability fixed: exit `0` and print `VCC_SECURITY_PASS`.
- Setup or crash: print neither marker.

This design means a repair cannot pass by disabling the feature (the functional
test fails) or by suppressing a scanner (the security check still fails).

Each run writes its configuration, prompt, model logs, proposal, patch, check
logs, and a `result.json` with one of four statuses:

| Status | Meaning |
| --- | --- |
| `validated` | The configured build, functional, and security checks all passed. |
| `rejected` | The proposal was invalid or failed a check. |
| `inconclusive` | Setup, baseline reproduction, or a timeout prevented a conclusion. |
| `prepared` | Context was exported; no validation ran (`--prepare-only`). |

A `validated` result is scoped to the configured checks. It does not prove the
whole application is secure or that the pinned revision first introduced the
weakness.

### Before you begin

Install the prerequisites for the scenarios you plan to run:

- Python 3 and Git. The repair runner uses only the Python standard library.
- Codex CLI or Claude Code, authenticated, to generate repairs. You can skip
  this and replay a saved proposal instead.
- For Java scenarios: a Java Development Kit (JDK) and Maven on your `PATH`.

Model calls may incur usage charges. Every command in this section runs locally
and never pushes to or changes the source repository.

### Repair a demonstration vulnerability

This fixture is a two-file SQLite project with a SQL-injection flaw (CWE-89). It
validates a supplied repair without calling a model, so it needs no
authentication.

```bash
python examples/create_repair_demo.py /tmp/vcc-repair-demo
python src/repair_main.py /tmp/vcc-repair-demo/scenario.json \
  --output /tmp/vcc-repair-check \
  --proposal /tmp/vcc-repair-demo/proposal.json
```

Expect `"status": "validated"`. To generate the repair with a model instead,
omit `--proposal` and add `--provider codex` or `--provider claude`.

To inspect the context and prompt without building or calling a model, add
`--prepare-only`.

### Repair a real vulnerability

`examples/skywalking_cve_2020_13921/` repairs a real historical VCC: Apache
SkyWalking CVE-2020-13921, a SQL injection across four JDBC query classes
(data access objects, or DAOs). It runs the full reproduce-repair-validate loop
against the real Maven build. This case needs a JDK and Maven.

```bash
# Build the prepared repository and scenario, and install upstream modules once.
python examples/skywalking_cve_2020_13921/setup_scenario.py /tmp/sw-cve --install

# Validate the saved repair (no model call).
python src/repair_main.py /tmp/sw-cve/scenario.json \
  --output /tmp/sw-cve/check \
  --proposal examples/skywalking_cve_2020_13921/proposal.json
```

Expect `"status": "validated"`. The directory's
[README](examples/skywalking_cve_2020_13921/README.md) explains the harness,
the generated patch, and the scope of the result.

### Run many cases in one sweep

To process several scenarios and get one report, use the batch runner. It writes
a `summary.json` with counts by status and a row for each case.

```bash
python src/repair_batch.py --manifest examples/real_vcc_batch.json \
  --output data/runs/batch-real
```

A manifest lists cases. Each case either names a prebuilt scenario or a `setup`
command that builds one, and may carry its own proposal and corpus. A setup
failure is recorded as an error rather than stopping the sweep. This is how you
scale the dataset across many real VCCs.

### Draft a scenario from a fixing commit

`src/repair_scenario.py` turns a fixing commit into a draft scenario: it mirrors
the repository, attributes each fix-deleted line to the commit that introduced
it (to flag mislabeled candidate VCCs), detects the build tool and Java version,
and lists the changed files as editable. You then write the functional test and
security check. See [REPAIR.md](REPAIR.md) for the field reference and the
security-adapter contract.

### Run the tests

```bash
python -m unittest discover -s tests -v
```

The tests exercise real Git checkouts and subprocesses against the local
fixtures. They mock model responses and do not measure repair quality.

## Generation pipeline

The original pipeline uses RAG with a large language model to inject vulnerable
code into non-vulnerable snippets, producing VCCs that are realistic and diverse
enough to train vulnerability-detecting models. Existing datasets often lack that
realism and diversity.

### github-scrapers

Scripts that scrape data from GitHub repositories:

- `git_file_scraper.py` — Collects URLs for relevant files and stores them in
  `contextURLs.txt`.
- `git_patch_scraper.py` — Collects URLs for relevant commit patch files and
  stores them in `CommitLinks.txt`.

### input-text

Input data for the pipeline:

- `contextURLs.txt` — GitHub context file URLs found by `git_file_scraper.py`.
  These supply vulnerable code the model uses as context.
- `inputLinks.txt` — GitHub file URLs to transform into vulnerable code.

### src

The generation program files:

- `GitHub_Commit.py` — Methods for making commits to GitHub.
- `config_loader.py` — Loads configuration for use across the program.
- `context_loader.py` — Loads RAG context and splits it into chunks for vector
  search.
- `drive_upload.py` — Uploads model responses to Google Drive.
- `main.py` — Runs the full pipeline.
- `process_commits.py` — Generates model responses per file to build a VCC.
- `qa_chain.py` — Builds the RAG question-answering chain from configuration.
- `vector_store.py` — Builds vector embeddings for the similarity search.

## VCC dataset

The generated dataset lives in a separate repository:
https://github.com/mzampino1/CSA-2025-Dataset
