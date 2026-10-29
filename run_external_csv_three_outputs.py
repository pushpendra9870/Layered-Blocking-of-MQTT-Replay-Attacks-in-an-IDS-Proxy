#!/usr/bin/env python3
"""Run the project's three existing configurations on a prepared external CSV dataset.

Place this file in the mqtt_real_dataset_eval project root and run
prepare_external_replay_csv.py first. No detector code or configuration is changed.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNNERS = [
    ("output1_no_ids", "run_output1_no_ids.py"),
    ("output2_layered_ids", "run_output2_layered_ids.py"),
    ("output3_layered_ids_minimized", "run_output3_layered_ids_minimized.py"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", default=str(ROOT / "external_data" / "csv_replay_test_ready.json"),
                    help="Prepared JSON created by prepare_external_replay_csv.py")
    ap.add_argument("--out-root", default=str(ROOT / "results" / "csv_external"),
                    help="Root folder for each output's logs and metrics")
    ap.add_argument("--broker", choices=["mosquitto", "mini"], default="mosquitto",
                    help="Use a private Mosquitto broker or the bundled mini broker")
    ap.add_argument("--broker-port", type=int, default=18830)
    ap.add_argument("--proxy-port", type=int, default=18840)
    ap.add_argument("--replay-mode", choices=["same_conn", "new_conn"], default="same_conn",
                    help="Existing evaluator mode; same_conn is the default controlled replay test")
    ap.add_argument("--stop-on-error", action="store_true",
                    help="Stop after the first runner fails; default continues with remaining outputs")
    args = ap.parse_args()

    dataset = Path(args.dataset).expanduser().resolve()
    out_root = Path(args.out_root).expanduser().resolve()
    if not dataset.is_file():
        raise SystemExit(
            f"Prepared dataset not found: {dataset}\n"
            "Run prepare_external_replay_csv.py first, or pass --dataset <path>."
        )
    try:
        parsed = json.loads(dataset.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"Could not read prepared JSON dataset: {exc}") from exc
    if not isinstance(parsed, list) or not parsed:
        raise SystemExit("Prepared dataset must be a non-empty JSON list of packet records.")
    if not all(isinstance(r, dict) and "truth" in r and "scored" in r and "packet" in r for r in parsed):
        raise SystemExit("Dataset schema is not compatible with the project's live evaluator.")

    out_root.mkdir(parents=True, exist_ok=True)
    results = []
    print(f"Dataset: {dataset}")
    print(f"Records: {sum(1 for r in parsed if r.get('scored'))} scored")
    print(f"Output root: {out_root}\n")

    for name, runner in RUNNERS:
        runner_path = ROOT / runner
        if not runner_path.is_file():
            raise SystemExit(f"Required existing runner not found: {runner_path}")
        output_dir = out_root / name
        log_path = output_dir / "runner_console.log"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable, str(runner_path),
            "--dataset", str(dataset),
            "--out", str(output_dir),
            "--broker", args.broker,
            "--broker-port", str(args.broker_port),
            "--proxy-port", str(args.proxy_port),
            "--replay-mode", args.replay_mode,
        ]
        print("=" * 76)
        print(f"Running {name}")
        print("Command:", subprocess.list2cmdline(command))
        started = time.time()
        try:
            proc = subprocess.run(
                command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            console = proc.stdout or ""
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            proc_returncode = 999
            console = f"Runner launch failed: {type(exc).__name__}: {exc}\n"
        else:
            proc_returncode = proc.returncode

        log_path.write_text(console, encoding="utf-8")
        print(console.rstrip() or "(no console output)")
        elapsed = round(time.time() - started, 2)
        live_results_path = output_dir / "live_results.json"
        live_results = None
        if live_results_path.is_file():
            try:
                live_results = json.loads(live_results_path.read_text(encoding="utf-8"))
            except Exception:
                live_results = None
        results.append({
            "output": name,
            "runner": runner,
            "exit_code": proc_returncode,
            "elapsed_seconds": elapsed,
            "output_dir": str(output_dir),
            "console_log": str(log_path),
            "live_results": str(live_results_path) if live_results_path.is_file() else None,
            "metrics": live_results,
        })
        print(f"Finished {name}: exit={proc_returncode}, elapsed={elapsed}s")
        if proc_returncode != 0 and args.stop_on_error:
            break

    summary = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset),
        "dataset_scored_records": sum(1 for r in parsed if r.get("scored")),
        "broker": args.broker,
        "replay_mode": args.replay_mode,
        "note": "Uses the existing project runners and detector configurations; it does not modify IDS rules.",
        "runs": results,
    }
    summary_path = out_root / "external_csv_run_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n" + "=" * 76)
    print("EXTERNAL CSV EVALUATION SUMMARY")
    for result in results:
        metrics = result.get("metrics") or {}
        print(f"{result['output']}: exit={result['exit_code']}; "
              f"replays_sent={metrics.get('replay_sent', 'n/a')}; "
              f"replays_delivered={metrics.get('replay_delivered_to_subscriber', 'n/a')}; "
              f"blocking_rate={metrics.get('replay_blocking_rate_delivery', 'n/a')}")
    print(f"Summary JSON: {summary_path}")
    print("Each output's live_results.json and runner_console.log are in its output folder.")
    return 0 if results and all(r["exit_code"] == 0 for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
