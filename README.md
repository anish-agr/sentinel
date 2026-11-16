# Sentinel

Code and data for *What Coding Agents Do After a Guard Says No*, by Anish
Agrawal and Ayush Agrawal, accepted at NeurIPS 2026 (*Who Verifies the Agents?
Toward Reliable Agent Development*). The paper is
[`paper/paper.pdf`](paper/paper.pdf).

Sentinel is a pre-execution guard for AI coding agents. A hook sends each tool
call to the guard before it runs. If a rule matches, the call is blocked and the
agent receives a refusal message as the tool's result. The paper varies that
message and records what the agent does next.

## Contents

| Path | Contents |
|---|---|
| `crates/` | The guard, recorder, hooks and CLI (Rust) |
| `ui/` | Timeline page served by the daemon |
| `paper/paper.pdf` | The paper |
| `paper/scripts/` | Collection and analysis scripts |
| `paper/scripts/denials/tasks.tsv` | The 240 tasks |
| `paper/data/denials*/` | Session logs, one directory per arm or model cell. `denials-api-*` are the Gemini API pilot and Run B. |
| `paper/data/later/` | Control and Opus max-effort sessions collected after the paper's numbers were fixed. No number in the paper uses them. |
| `paper/data/*.jsonl` | ATBench relabelling, developer policy statements and human rater labels |
| `paper/figures/` | Generated tables and figures |
| `paper/preregistration.md` | Hypotheses and analysis rules for the Claude Code ablation |
| `paper/run-b-declaration.md` | Stopping rule and contrasts for Run B |

## Build

```bash
cargo build --release
```

## Reproduce

```bash
python paper/scripts/analysis/responses.py --verify --allow-missing-reference
python paper/scripts/figures/tables.py --check
python paper/scripts/figures/plots.py --check
python paper/scripts/analysis/run_b_report.py
```

`responses.py --verify` reruns the outcome classifier and compares it with the
424 classifications reported for the archive. After `cargo build --release`,
running it without `--allow-missing-reference` also compares it with the
compiled classifier. `tables.py --check` and `plots.py --check` regenerate the
tables and figures from the logs and compare them with `paper/figures/`.
`run_b_report.py` prints Run B's confirmatory contrast (212 of 1,435 under
`full`, 0 of 779 under `defer`) and the four arms that do not name the override
(0 of 4,146). The Run B harness and its cell admission check are
`paper/scripts/api/run_api.py` and `paper/scripts/api/verify_cells.py`.

The scripts need Python 3.8 or later and no other packages.

## Notes

- Paths in the logs are rewritten to placeholders such as `/home/author/repo`.
  Usernames, email addresses, machine names and access tokens are removed.
  Session names and path structure are kept, so the analyses give the same
  results.
- The guard in `crates/` has 22 rules. The 22nd, `guard.control_plane`, was
  added after collection. Every number in the paper comes from the 21-rule build
  whose binary digests are in `paper/guard-binaries.sha256`.
  `paper/scripts/check-arms.sh` checks a built hook against those digests and
  each arm's refusal text.

## License

[Apache License 2.0](LICENSE)
