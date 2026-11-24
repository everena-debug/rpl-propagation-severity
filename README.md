# rpl-propagation-severity

Instrumented Contiki-NG / Cooja testbed and analysis pipeline for measuring the
temporal propagation and entropy-weighted severity of seven RPL routing attacks,
accompanying the paper "An Entropy-Weighted Severity Index and Temporal
Propagation Model for RPL Routing Attacks in IoT Networks" (IJIES).

## Repository structure

- `root/`, `node/`, `attacker/` — Contiki-NG applications for the sink, the honest
  motes, and the adversary motes (the attacker hooks are applied to the RPL-Lite stack).
- `tools/` — scenario generation, headless run harness, and analysis scripts:
  - `build_csc.py` — builds a Cooja scenario (.csc) for a given size, placement, attack, loss, and seed.
  - `gen_matrix2.py` / `run_matrix2.sh` — generate and run the main 30-cell matrix.
  - `gen_extra.py` / `run_extra.sh` — dense attacker-position and drop-rate intensity runs.
  - `add_instrumentation_hooks.py` — inserts the control-traffic and parent-edge hooks.
  - `analyze_log.py`, `propagation.py` — per-run impact and propagation metrics.
  - `ar_rir_fix.py` — recomputes attack reach and rank-inconsistency with the corrected definitions.
  - `transit_baseline.py` — attack-free transit through the would-be-attacker node.
- `scenarios_manifest.csv`, `scenarios_extra.csv` — scenario and seed manifest with attacker IDs.
- `results/` — processed per-run tables (`summary.csv`, `prop_summary.csv`, `ar_rir_fixed.csv`, `transit_baseline.csv`).
- Raw labelled traces are provided as a release asset (see Releases), one `*_log.txt` per run.

## Dependencies

- Contiki-NG at git commit `7f844118`, with Cooja (Java, Gradle).
- Python 3.8 or later (standard library only).

## Reproduce

Run from `contiki-ng/examples/rpl-security`:

```bash
# main matrix (15 seeds)
SEEDS=15 python3 tools/gen_matrix2.py
bash tools/run_matrix2.sh

# dense-position and intensity runs
python3 tools/gen_extra.py
bash tools/run_extra.sh

# corrected propagation metrics and the attack-disabled baseline
python3 tools/ar_rir_fix.py results > results/ar_rir_fixed.csv
python3 tools/transit_baseline.py results > results/transit_baseline.csv
```

`results/summary.csv` and `results/prop_summary.csv` hold one row per run; the tables
and figures in the paper are computed from these.

## License

Released for review and reproduction. See the paper for citation.
