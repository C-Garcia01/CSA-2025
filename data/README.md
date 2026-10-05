# CSV repair corpus

The all-language import and experiment splits are now in `all_repairs/` and `splits/`.
Use `splits/rag/repairs.jsonl` for experiments. The older Java collection below is
retained for the original demo, but is not the split experiment corpus.

The CSV contains 70 records across seven CWEs. All 55 referenced fixing commits
were downloaded. Nine repairs have assistant source inspections; seven are in
RAG and two belong to evaluation partitions. This is not independent human
review or historical runtime validation.

| File | Purpose |
| --- | --- |
| `splits/rag/repairs.jsonl` | Reviewed historical before/after transformations for retrieval |
| `splits/rag/candidates.jsonl` | RAG partition repairs still carrying their review status |
| `splits/dev/queries.jsonl` | Development targets for tuning the pipeline |
| `splits/test/queries.jsonl` | Held-out targets for final evaluation |
| `splits/dev/references.jsonl`, `splits/test/references.jsonl` | Evaluator-only historical repairs |
| `splits/quarantine.jsonl` | Missing VCCs and known conflicting VCC labels |
| `splits/coverage.json` | All ten requested CWEs, counts, gaps and input hashes |

Queries omit fixing commits and repaired code. They retain candidate labels;
they are not runnable scenarios or proven VCCs. Quarantined rows remain in the
audit manifest but are excluded from queries. A missing VCC does not invalidate
a separately inspected historical repair as retrieval evidence.

Repository, CVE, commit and exact repair-snippet groups cannot cross partitions.
The seed makes the split reproducible for unchanged inputs. Adding records or
reviews can change assignments; freeze the generated files before experiments.
The splitter reserves reviewed CWE coverage for RAG, then held-out CWE coverage,
then targets 60/20/20 by group. It does not force misleading row percentages.
Near-duplicate code and related forks still need further review.

CWE-15, CWE-81 and CWE-83 have no CSV records. CWE-134 and CWE-606 have no
independent held-out repository after RAG reservation. Do not relabel CWE-80
examples to fill missing XSS subclasses. Other-language repairs are retained
with repository provenance; they do not establish Java-specific coverage.

Build commands from the repository root:

```bash
python src/import_repair_csv.py "/home/chris/Downloads/Real World Java VCC Datasets - VCCs.csv" --output data/all_repairs --reviews data/repair_reviews.json --all-languages
python src/split_repair_corpus.py --source data/all_repairs --output data/splits
```

Run an existing scenario with `--corpus data/splits/rag/repairs.jsonl`.
Keep evaluation references out of prompts and model working directories.
Use development cases to tune retrieval and tests; freeze those choices before
final test runs. Each target still needs pinned dependencies, a baseline security
reproducer, protected functional tests and repair validation. Before/after and
transformation examples share a record and a partition; they are not split apart.

The all-language source import preserves CSV CWE classifications. Some referenced
commits are renames, reverts or unrelated changes; unreviewed imports are not
automatically trusted repairs. Retrieval remains lexical and exact-CWE filtered.

Source: `/home/chris/Downloads/Real World Java VCC Datasets - VCCs.csv`.

The import retains 70 detailed records and matches all 31 left-table records by repository/CVE/VCC identity. The tables are not aligned by row. There are 35 Java-related records referencing 21 fixing commits, all downloaded.

Five fixes have assistant source reviews and are eligible for retrieval:

| Project | CVE | CWE | Repair pattern |
| --- | --- | --- | --- |
| Apache Ranger | CVE-2016-2174 | CWE-89 | Named queries with typed, bound values |
| Spring Data JPA | CVE-2016-6652 | CWE-89 | Validate sort expressions and preserve explicit trusted opt-in |
| Apache SkyWalking | CVE-2020-13921 | CWE-89 | Bind search values across query implementations |
| Undertow | CVE-2018-1067 | CWE-113 | Check header bytes after character narrowing |
| Apache Tomcat | CVE-2019-0232 | CWE-78 | Validate decoded CGI arguments on Windows |

Review scope is code inspection only. No historical Java project builds or security tests were run. Existing test additions are described where inspected. The other 16 fixes remain unreviewed candidates.

Before/after code is extracted around the fixing commit, not paired directly between a VCC and a much later fix. Original VCC assertions, CSV row numbers, source records, known conflicts, commit URLs, exact fix parents and source checksums are retained.

`repair_reviews.json` contains explicit review decisions. `java_repairs/repairs.jsonl` is the usable RAG collection. `java_repairs/import_report.json` is the import audit. Download caches and generated runs are ignored by Git.
