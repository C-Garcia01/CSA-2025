# Repair prototype

This entry point repairs a pinned vulnerable repository using selected repository files and reviewed repair examples. The existing generation scripts are unchanged.

It uses Python's standard library, Git, and either Codex CLI or Claude Code. No local GPU, embeddings service, or LangChain installation is required.

## Run the local demonstration

The fixture uses SQLite and spans two source files. It is an educational example, not a historical CVE or an evaluation dataset.

```bash
python examples/create_repair_demo.py /tmp/vcc-repair-demo
python src/repair_main.py /tmp/vcc-repair-demo/scenario.json --output /tmp/vcc-repair-check --proposal /tmp/vcc-repair-demo/proposal.json
```

This validates a supplied two-file repair without calling a model. The original permits query manipulation; the repair binds the name as a value and preserves ordinary searches and quoted names.

To generate a proposal with either CLI, use a new output directory:

```bash
python src/repair_main.py /tmp/vcc-repair-demo/scenario.json --output /tmp/vcc-codex-run --provider codex
python src/repair_main.py /tmp/vcc-repair-demo/scenario.json --output /tmp/vcc-claude-run --provider claude
```

The default provider invokes the installed `claude` (Claude Code) CLI. Run `claude auth login` to sign in with your Claude subscription; the pipeline uses that CLI login. Authenticate the selected CLI first. Add `--model MODEL` to select a specific model. Without it, Claude Code uses Opus 4.8 (`claude-opus-4-8`), the default provider and model. With `--provider codex`, Codex uses its configured default. Model calls may incur usage charges.

## Run the Java demonstration

This fixture is a real Maven/JDK 8/H2 project, exercised through the real build, functional and security tooling. It reproduces the concatenated `id in ('...')` SQL-injection pattern (CWE-89) and is an educational example, not a historical CVE. It needs `mvn` and JDK 8 on `PATH`; the first run downloads dependencies.

```bash
python examples/create_java_repair_demo.py /tmp/vcc-java-demo
python src/repair_main.py /tmp/vcc-java-demo/scenario.json --output /tmp/vcc-java-check --proposal /tmp/vcc-java-demo/proposal.json
```

The original leaks a second table through a crafted id and fails the security probe; the repair binds each id as a parameter, so the probe passes and the functional test still returns the requested names. A repair that empties the result instead is rejected on the functional test. Omit `--proposal` to generate with `--provider codex` or `--provider claude`.

The `security_check.py` adapter follows the marker contract below: it runs the injection probe test and reports the security property, not just the exit code. It is the template to replicate for real cases.

## Worked example: a real VCC validated end to end

`examples/skywalking_cve_2020_13921/` repairs a real historical VCC (Apache SkyWalking, CVE-2020-13921, CWE-89) through the full reproduce → repair → validate loop. The fix spans four JDBC query DAOs, so the repair is multi-file. `setup_scenario.py` rebuilds the prepared repository and scenario; the harness, the `gpt-6-astra` proposal, the validated patch and the run report are included. See that directory's README to run it. It needs JDK 8 and Maven.

To inspect retrieval without running the project or a model:

```bash
python src/repair_main.py /tmp/vcc-repair-demo/scenario.json --output /tmp/vcc-context --prepare-only
```

Output directories must not already exist. Runs never push or change the source repository.

## Configure a real case

Use the generated `scenario.json` as a starting point.

| Field | Meaning |
| --- | --- |
| `repository` | Local Git repository or clone URL; local paths are relative to the scenario |
| `repository_id` | Canonical owner/project identifier for excluding same-project examples |
| `revision` | Full 40-character SHA of the vulnerable snapshot |
| `cwe`, `group` | Exact weakness identifier and shared CVE/seed group |
| `flow` | Source, sink, intermediate symbols, failure mechanism and required behavior |
| `context_files` | Complete UTF-8 files to include at the pinned revision |
| `editable_files` | Exact tracked source paths the generator may change |
| `protected_files` | Tracked tests, harnesses and other files that must not be editable |
| `corpus` | JSONL repair collection, relative to the scenario |
| `build_command` | Argument list for building the project |
| `test_command` | Argument list for functional tests |
| `security_command` | Argument list for the security assertion adapter |
| `environment` | Record the runtime, services, dependencies and environment identity |

Commands run from the checkout without a shell. Each command must wait for its work to finish. Commands and repositories must be trusted. For unfamiliar projects, run this prototype inside a disposable container or VM; cloned directories alone are not an execution sandbox. The prototype records environment information but does not provision containers or dependencies.

The security adapter must use this contract:

- Vulnerability reproduced: exit 1 and print `VCC_SECURITY_FAIL` on its own line.
- Security assertion satisfied: exit 0 and print `VCC_SECURITY_PASS` on its own line.
- Crashes or setup failures: do not print either marker.

Only print a marker after checking the actual security property. A matching exit code alone is insufficient. Include valid boundary cases and multiple attack variants in the adapter. The generator cannot change files outside `editable_files`; the runner also checks all tracked file hashes around validation.

Optional settings: `timeout` (300 seconds per check), `agent_timeout` (300 seconds), `max_attempts` (2, at most 5), `top_k` (3), `context_limit` (60000 characters), `excluded_examples` (record IDs), and `java_context` (`{"depth": 1, "max_files": 5000, "max_bytes": 8000000}` to attach the bounded Java import/type inventory to the prompt). Set `environment.submodules` to `true` for repositories whose build needs Git submodules.

## Draft a scenario from a fixing commit

`import_repair_csv.py` records a fixing commit and candidate introducing commits but not a runnable scenario. `repair_scenario.py` mirrors the repository, qualifies each candidate VCC against the fix, detects the build tool and Java version, and writes a draft `scenario.json`.

```bash
python src/repair_scenario.py --record record.json --output scenario.json
python src/repair_scenario.py --repository-id apache/skywalking \
  --fix-sha 4ce2e9e87398efcee4b646af1143f4dc2ae10dc7 --cwe CWE-89 --group CVE-2020-9483 \
  --files path/to/Vulnerable.java --candidate <vcc-sha> <vcc-sha>
```

Qualification blames the lines the fix deleted at the fix parent and attributes each to the commit that introduced it. A candidate that introduced none of the fixed lines is an incorrect label, not a genuine VCC. This is line attribution, not SZZ; it does not prove the weakness was first reachable at that commit.

The draft sets `revision` to the fix parent, copies the changed files into `editable_files` and `context_files`, and records the detected build. It leaves `test_command` and `security_command` as `TODO`: the curator writes the functional test and the security adapter, and confirms the vulnerable snapshot before running. Mirrors are cached under `data/runs/mirrors`.

## Batch execution

`repair_batch.py` runs several scenarios and summarizes outcomes. Each scenario keeps its own output directory and `result.json`; `summary.json` records counts by status and the reason for every non-validated run.

```bash
python src/repair_batch.py data/scenarios --output data/runs/batch-01 --corpus data/splits/rag/repairs.jsonl
```

Pass `--prepare-only` to export context and prompts without validation. Arguments may be scenario files or directories of them.

To run real cases that must be built first, pass a manifest instead. Each case either names a prebuilt `scenario` or a `setup` command that builds one and prints its path (`{work}` is replaced with a per-case directory); a case may also carry its own `proposal` and `corpus`. `examples/real_vcc_batch.json` runs the SkyWalking example this way.

```bash
python src/repair_batch.py --manifest examples/real_vcc_batch.json --output data/runs/batch-real
```

## Retrieval

Repository context is selected explicitly from the supplied flow. Automatic source/sink discovery, call-graph expansion, and CodeQL integration are not implemented.

For historical repairs, use the fields in `examples/repair_record.json`. Put one complete JSON object on each line of the corpus file. Only records with `reviewed: true` are eligible; set that flag only after reviewing the evidence.

Retrieval filters by exact CWE and excludes the target repository, shared seed group, explicit exclusions, and exact duplicate before/after pairs. It ranks remaining examples by lexical overlap with the flow description. This is a lightweight RAG baseline, not embedding retrieval. Transformation guidance stays attached to its before/after example and validation evidence.

Use the same `group` for copied or derived examples. Automatic near-duplicate, fork-family and future-fix detection are not implemented. Keep the target's actual fix out of the generation corpus and supplied context. A reviewed flag is curator metadata, not automatically verified proof.

An empty corpus is supported for repository-only comparisons. The demo deliberately uses an empty corpus rather than inventing reviewed historical evidence.

## Use the downloaded VCC CSV

The CSV importer reads the two side-by-side tables independently and joins their records by repository, CVE and VCC SHA. It preserves all detailed records, then downloads the fixing commits associated with Java records.

```bash
python src/import_repair_csv.py "/home/chris/Downloads/Real World Java VCC Datasets - VCCs.csv" --output data/java_repairs --reviews data/repair_reviews.json
```

GitHub downloads use an authenticated `gh` CLI. Before/after source snapshots use public raw GitHub URLs. Downloads are cached; rerunning the command reuses them.

`data/java_repairs/repairs.jsonl` contains five source-reviewed examples from this CSV. `candidates.jsonl` retains the other downloaded fixes with `reviewed: false`. `vcc_index.json` preserves CSV associations and known conflicting VCC labels. `import_report.json` records counts, failures and the input checksum.

These reviews were performed by Codex through source inspection. They are not independent human reviews or runtime validation. Review explanations and limitations are stored in `data/repair_reviews.json` and each retrieval record. A repair review does not establish that a CSV introducing-commit label is correct.

Use the real corpus with any configured scenario:

```bash
python src/repair_main.py /tmp/vcc-repair-demo/scenario.json --output /tmp/vcc-rag-run --corpus data/java_repairs/repairs.jsonl --provider codex
```

Omit `--proposal` to generate a new repair. The SQL demo then retrieves actual Java repair patterns but still repairs a Python/SQLite fixture; it does not reproduce those Java CVEs. For Java experiments, configure a real Java checkout and its own functional/security adapters.

Historical before/after snippets are changed hunks at the fixing commit's parent and the fixing commit. They are not assumed to be the VCC snapshot. Complete source snapshots for reviewed files are cached with checksums and exact revision URLs. The importer never marks an unseen fix reviewed automatically.

## Generation and validation

The CLI receives the context bundle and returns JSON edits with `path`, `old`, and `new`. Each old string must match exactly once. The runner validates every edit before applying any of them to a fresh checkout. Multiple files are supported; new files, deletions, symlinks and submodules are outside this prototype's scope.

Claude runs with tools disabled. Its JSON reply is validated locally, with up to two format-correction retries within one timeout budget; all attempts are logged. This avoids the Claude CLI `--json-schema` tool serialization path. Codex runs in read-only mode from a separate directory and is instructed to return edits. Neither receives a writable target checkout through this workflow. This is not a confidentiality boundary: use separate execution environments for adversarial generation or truly hidden evaluation tests.

Baseline build and functional checks must pass, and the original security assertion must fail with the expected marker. The repaired checkout must then pass all three checks. Retries start from the original revision and receive only the previous failure reason.

## Results

Each run saves configuration, retrieved context, prompt, CLI logs and responses, proposals, patches, check logs, and `result.json`. Accepted runs also export `repair.patch` and file/context/corpus hashes. The output checkout retains the pinned Git history. No new commits are created.

- `prepared`: context exported; no validation performed.
- `validated`: configured checks passed; independent review is still pending.
- `rejected`: the proposal was invalid or failed validation.
- `inconclusive`: setup, baseline reproduction, execution or timeout prevented a conclusion.

`validated` is scoped to the supplied checks. It does not mean the entire application is secure or that the supplied SHA is a proven introducing commit. Reports use `kind: synthetic_repair` and `review_status: not_reviewed`.

The generated patch is V → R, a repair of the supplied vulnerable snapshot. It is not a new historical VCC. Creating a P → R sibling feature commit requires separate parent and behavior validation.

## Development checks

```bash
python -m unittest discover -s tests -v
```

The tests exercise real Git checkouts and subprocesses with the local fixture. CLI response handling is mocked; these tests do not measure model repair quality.
# Experiment splits

Use `data/splits/rag/repairs.jsonl` as the corpus for split experiments.
`data/README.md` describes the CSV importer, development/test queries and
evaluator-only references. Coverage and missing CWEs are recorded in
`data/splits/coverage.json`. These targets still require runtime scenarios.


# Automatic preparation from a VCC

`python src/repair_main.py <GitHub-commit-URL>` creates its output directory and
uses the configured model for both preparation and repair. A bare SHA resolves
in the current repository, or an optional `--repository` supplies its location.
The original scenario JSON interface continues to work.

`repair_auto.py` snapshots the supplied commit and gives a bounded inventory,
changed files, commit diff, build files, existing tests and detected executable
paths to a structured preparation call. The model returns a CWE, editable/context
paths, argv commands, and any new files confined to `.vcc-generated/`. Existing
files cannot be overwritten by preparation. Existing test paths are excluded
from editable candidates; generated harnesses and every non-editable tracked
file are protected by the existing hash checks. Generation uses at most two
eligible historical RAG examples by default, with the existing exclusion rules.

The preparation call cannot return production edits. The repair call uses the
normal edits schema and cannot modify protected files. An established vulnerable
baseline is required before invoking repair generation. A missing CLI, invalid
plan, failed build, unproven vulnerability, or other setup error records an
inconclusive result with no accepted pairs. Repair rejection is retained as a
rejection. There is no automatic replay of saved fixes on the commit-only path.

Accepted repairs are committed in the disposable checkout and exported to a
Git bundle. `input_vcc` identifies the supplied commit; `prepared_revision`
identifies the same production code plus generated checks; `fixed_commit`
identifies its repaired child. CSV rows represent changed files, so a multi-file
repair has several rows sharing those commit IDs. Full code is in `pairs.jsonl`;
`pairs.csv` preserves metadata and SHA-256 hashes without code columns.

The corpus remains read-only. New pairs require separate review and splitting
before use as retrieval examples. Automatically generated validation is marked
not independently reviewed. This is bounded, one-pass scenario preparation;
it does not guarantee successful setup or repair of arbitrary repositories.
`--prepare-only` still calls the preparation model, but skips build/tests and
repair generation. Output directories are never overwritten.
