# Reproducing the paper's experiments

Everything in the paper (`paper/main.pdf`) is generated from files in this project. Nothing is typed by hand:
tables come from `results/**` via `bench/make_tables.py`, data figures from `bench/analyze.py`, diagrams from
`paper/figures/make_diagrams.py`.

> **Status.** Executed on Linux (Ubuntu 24.04, Python 3.12.3, Mosquitto 2.0.18, psutil 7.2.2, **1 vCPU, 3.9 GB RAM**).
> The Windows 11 commands below were **not executed on Windows**. Absolute performance numbers depend on hardware;
> the detection counts (80/0/4000/0, 770 FP for the HMAC rule, ...) are deterministic and should reproduce exactly.

## 0. Requirements
| Need | For |
|---|---|
| Python 3.10+ | everything |
| Mosquitto 2.x (`mosquitto.exe` in `C:\Program Files\mosquitto\` or `MOSQUITTO_EXE`) | all live runs and socket tests (`--broker mini` = bundled fallback) |
| `pip install psutil numpy scipy matplotlib` | benchmark + analysis (the IDS itself needs no packages) |
| TeX Live / MiKTeX with `IEEEtran`, `booktabs`, `microtype`, `cite` | compiling the paper |

```powershell
cd C:\path\to\mqtt_real_dataset_eval
py -3 -m venv .venv ; .\.venv\Scripts\Activate.ps1      # if blocked: Set-ExecutionPolicy -Scope Process Bypass
pip install psutil numpy scipy matplotlib
& "C:\Program Files\mosquitto\mosquitto.exe" -h           # prints the version
```
Linux/macOS: same commands with `python3` and `source .venv/bin/activate`.

## 1. Detection experiments on Mosquitto (existing pipeline; ~3 min)
```
python run_all.py          # 52 tests, Outputs 1/2/3 (live), reconnecting-attacker mode, 2nd real window, external CSV, equivalence
```
Writes `results/comparison.md`, `results/output*/`, `results/offline/` (incl. `seq_window_sensitivity.json`),
`results/test_report_mosquitto.txt`. Expected: Output 1 leaks 80/80 replays; Outputs 2/3: TP 80, FP 0, TN 4000, FN 0,
Mosquitto receives 4,000 PUBLISH; decisions identical for Output 2, Output 3 and the offline engine (4,080).

## 1b. External CSV dataset (integrated; ~1 min)
Input: `external_data/replay_attack.csv` (supplied; 29,081 rows, 4 topics, labels `''` / `replay attack`; provenance not documented).
```
python prepare_external_replay_csv.py                    # -> external_data/csv_replay_test_ready.json + csv_replay_manifest.json
python run_external_csv_three_outputs.py                 # 3 configs on Mosquitto -> results/csv_external/
python eval/csv_offline_eval.py                          # existing rules + layered, offline, SYNTHETIC PUBACKs -> results/csv_external/offline/
python eval/make_csv_dup_variant.py                      # OUR synthetic variant: same replays with DUP=1
python run_external_csv_three_outputs.py --dataset external_data/csv_replay_test_ready_dup1.json --out-root results/csv_external_dup1
python eval/csv_offline_eval.py --dataset external_data/csv_replay_test_ready_dup1.json --out results/csv_external_dup1/offline
```
(`run_all.py` does all of this automatically; `--skip-csv` skips it.) The CSV is **not a packet capture**: QoS 1, packet IDs, DUP=0,
one connection per topic and ACKs are synthesized; blank-label rows are treated as negatives without independent verification;
1,153 of 1,493 `replay attack` rows are reconstructed as exact replays (exact topic+payload match with an earlier row), the other
340 are excluded. Expected: C1 leaks 1153/1153; C2/C3 TP 1153, FP 0, FN 0, Mosquitto receives 27,588 PUBLISH; offline all three
detectors score 1153/0/0 on DUP=0, and on the DUP=1 variant the Packet-ID rule scores 0/0/1153 while HMAC and layered score 1153/0/0.

*Changes made to the supplied scripts (diff against your originals is 16 + 2 lines):* default CSV/output paths now point to
`external_data/` (keeps `external_eval/` pristine); a guard excludes and reports any label other than blank / `replay attack`
instead of silently treating it as benign. No detector rule or configuration was changed.

## 2. Performance benchmark (new; ~15 min)
```
python -m bench.run_bench --reps 5 --scale 10 --rate 400 --out results/bench
```
* Starts a private **quiet** Mosquitto, the proxy (Configs 2/3) and a load driver per run; reads CPU time and RSS of
  *broker and proxy only* with psutil; 5 repetitions x 3 configurations x {saturation, paced}, order rotated per
  repetition, one discarded warm-up per cell.
* Interrupted? Re-run the same command with `--resume` (skips finished cells; `--max-runs N` time-boxes a session).
* Raw per-run data: `results/bench/raw_runs.jsonl`; environment: `results/bench/meta.json`.

## 3. Scenario matrix and detector micro-benchmark (new; ~2 min each)
```
python -m bench.scenarios                 # 13 scripted scenarios x 3 configs on Mosquitto (debug log = ground truth)
python -m bench.bench_engine --reps 7     # per-decision time, no sockets
```

## 4. Tables, figures, paper
```
python bench/analyze.py                   # results/bench/summary.json + paper/figures/fig5..fig7 (.pdf/.png)
python bench/make_tables.py               # paper/tables/*.tex
python paper/figures/make_diagrams.py     # paper/figures/fig1..fig4 (fails if any label overflows its box)
cd paper ; pdflatex main ; bibtex main ; pdflatex main ; pdflatex main      # -> main.pdf (8 pages, US Letter)
```

## 5. What each paper element comes from
| Paper element | Source |
|---|---|
| Tab. I (dataset) | `external_eval/fixed_dataset.json` (computed) |
| Tab. II, Fig. 5(a,b) | `results/offline/offline_results.json`, `results/output2|3*/live_results.json`, `bench/raw_runs.jsonl` |
| Fig. 5(c) | `results/offline/seq_window_sensitivity.json` |
| Tab. III | `results/bench/scenario_matrix.json` (Mosquitto log counts) |
| Fig. 6, Tab. IV | `results/bench/raw_runs.jsonl` (paced) + `engine_microbench.json` |
| Fig. 7, communication-overhead numbers in Sec. VII-E | `results/bench/raw_runs.jsonl` (saturation), proxy byte counters, `results/bench/summary.json` |
| Micro-benchmark numbers in Sec. VII-C | `results/bench/engine_microbench.json`, `appfeed_microbench.json` |
| Tab. V (external CSV), Sec. VII-G | `results/csv_external/`, `results/csv_external_dup1/` (live + offline) |

## 6. Known caveats of these measurements (also in the paper, Sec. VIII)
One vCPU shares load generator, subscriber, proxy and broker; a 2-3 ms shoulder in ACK latency appears in *all*
configurations including No IDS (not caused by the IDS); the Python proxy logs every decision with a flush; the
benchmark here ran in three resumable sessions (order rotation preserved); Mosquitto 2.0.18 only.
