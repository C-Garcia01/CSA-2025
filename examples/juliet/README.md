# Juliet Java 1.3 dataset

Imports the repository's ten CWEs (15, 78, 80, 81, 83, 89, 113, 129, 134,
606) from `2017-10-01-juliet-test-suite-for-java-v1-3.zip` into a **separate
Git repository**. No dataset payload belongs in this code repository.

The archive yields 15,678 canonical source files, 9,546 multi-file case groups,
and 258 flow-01 bad/good reference pairs. All 15,678 files compiled with
Temurin 8.0.504. Only ten representative bad-only adaptations (one per CWE)
have protected behavioral checks: all ten reproduced the configured weakness
and passed their saved assistant repair. These counts are different populations;
compilation and Juliet-provided good methods do not establish validated repairs.

## Reproduce

Run from this fork's root. Set `ARCHIVE`, `JULIET_DATASET`, `JAVA_HOME`, and `H2`
to your archive, a new separate dataset directory, a JDK 8 home, and an H2
1.4.200 jar. The dataset directory may be inside ignored `data/runs/`.

```bash
python src/import_juliet.py "$ARCHIVE" --output "$JULIET_DATASET/imported"
python examples/juliet/setup.py "$ARCHIVE" --output "$JULIET_DATASET" \
  --java-home "$JAVA_HOME" --h2 "$H2"
python src/repair_batch.py --manifest "$JULIET_DATASET/manifest.json" \
  --output data/runs/juliet-check
python examples/juliet/compile_suite.py --dataset "$JULIET_DATASET" \
  --archive "$ARCHIVE" --java-home "$JAVA_HOME" --output data/runs/juliet-compile
python examples/juliet/export_dataset.py --dataset "$JULIET_DATASET" \
  --runs data/runs/juliet-check --baseline
# Commit the imported data and baseline export in the separate dataset repo.
python examples/juliet/export_dataset.py --dataset "$JULIET_DATASET" \
  --runs data/runs/juliet-check
# Commit repairs.jsonl, after snapshots, patches, reports, and updated bundles.
```

Output work/run/import directories must be new. Replaying the provided proposals
requires no model service. Add `--generate` to setup to omit saved proposals,
then use `repair_batch.py --provider codex` or `--provider claude` for fresh
model generation. `--prepare-only` on the batch runner exports prompts only.
The recorded ten repairs are assistant-authored proposals replayed through the
runner, not measurements of autonomous CLI generation.

Setup strips the supplied good methods, main method, inheritance and solution
labels from each target. The bad method is preserved with LF normalization,
except CWE-78 exposes the existing process exit status for observation. Protected
IO support routes database connections to the harness. The manifest pins each
synthetic vulnerable Git snapshot; accepted repairs become its immediate child
in the exported Git bundle. Neither commit is a historical VCC assertion.

Retrieval uses `data/splits/rag/repairs.jsonl`, filtered by exact CWE using the
existing pipeline. Seven targets have a historical example, including some
cross-language and different-mechanism examples. Three (15, 81, 83) have none.
Same-project Juliet reference methods are never added to the prompt. The
assistant authored the saved proposals after examining the vulnerable methods
and retrieved mechanisms/transformation guidance. No RAG effectiveness claim or
RAG/no-RAG controlled comparison is made.

## Validation scope

- 15: allowlisted `public`/`reporting` catalogs, observed through a simulated JDBC
  catalog sink. Does not prove database authorization in a deployed server.
- 78: Linux `ls` option/argument injection, including legitimate filenames with
  spaces; does not claim shell injection through `Runtime.exec(String)`.
- 80/81/83: HTML encoding at body, error-message and quoted-attribute servlet
  sinks. No real servlet container/browser; CWE-81 containers may already encode
  error messages. Attribute URL-scheme policy is outside these checks.
- 89: real H2 query execution with ordinary names, apostrophes and two SQL
  injection probes. A JDBC wrapper observes returned rows because Juliet only
  calls `getRow()` on its result.
- 113: CR/LF rejection at a simulated servlet header sink; no deployed serializer
  or byte-narrowing claim.
- 129: valid index boundaries and negative/oversized indices.
- 134: literal formatting, including percent directives and percent signs.
- 606: a declared inclusive 0..100 loop policy; rejects negative and larger
  counts while preserving valid boundary behavior.

The compiler runs source builds, never every Juliet main method (some start
servers, launch processes, or intentionally consume unbounded resources).
Security markers are emitted only after the explicit probe assertions. Unexpected
Java failures or harness errors are inconclusive, not repaired results. Logs,
original archive checksums, adaptations, full before/after text, proposals and
Git bundles retain the evidence. Independent review is pending.

Keep all flow variants of a `family` together in future train/dev/test splits.
These generated pairs are not a held-out benchmark; no evaluation split is
assigned, and the original Juliet archive contains solution annotations.
