"""One command that reproduces EVERYTHING on Mosquitto:
  1. test-suite on Mosquitto (fresh broker per test) [+ same suite on the bundled mini broker, secondary]
  2. Outputs 1/2/3 live on the real dataset (+ new_conn replay mode, + second real window)
  3. offline scoring (no broker involved by nature) incl. seq_window sweep
  4. Output2==Output3==offline equivalence, results/comparison.md/csv
Use --broker mini to run the bundled broker instead (zero-install fallback)."""
import argparse, csv, json, os, shutil, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import run_output
RES = ROOT / "results"
# long-running / separately generated results that run_all must NEVER delete
KEEP = {"extra_windows", "bench", "csv_external", "csv_external_dup1"}


def offline_signature(dataset):
    sys.path.insert(0, str(ROOT / "eval"))
    from offline_eval import LayeredAdapter, legacy_score
    from replay_ids.config import Config
    recs = json.loads(Path(dataset).read_text())
    ad = LayeredAdapter(Config(console=False))
    legacy_score.score(ad, recs)
    sig = {}
    for d in ad.decisions:
        sig.setdefault(f"dev-{str(d.client_id).split(':')[1]}", []).append(
            [d.classification, d.reason, d.action, d.detector])
    return sig


def tests(broker, name):
    env = dict(os.environ, MQTT_TEST_BROKER=broker)
    r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
                       cwd=ROOT, capture_output=True, text=True, env=env)
    (RES / name).write_text(f"BROKER USED BY SOCKET TESTS: {broker}\n" + r.stdout + r.stderr)
    last = [l for l in r.stderr.strip().splitlines() if l.strip()][-1]
    ran = [l for l in r.stderr.splitlines() if l.startswith("Ran ")][0]
    print(f"   tests on {broker}: {ran} -> {last} (exit {r.returncode})")
    return r.returncode


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--broker", default="mosquitto", choices=["mosquitto", "mini"])
    ap.add_argument("--skip-csv", action="store_true", help="skip the external-CSV step")
    a = ap.parse_args()
    if RES.exists():
        for p in RES.iterdir():
            if p.name not in KEEP:
                shutil.rmtree(p) if p.is_dir() else p.unlink()
    RES.mkdir(exist_ok=True)
    B = ["--broker", a.broker]
    print(f"== tests =="); rc = tests(a.broker, f"test_report_{a.broker}.txt")
    if a.broker == "mosquitto":
        tests("mini", "test_report_mini_broker_secondary.txt")
    out = {}
    for n in (1, 2, 3):
        print(f"== Output {n} ({a.broker}) =="); out[n] = run_output.main(n, B)
    print("== new_conn replay mode ==")
    nc = {n: run_output.main(n, B + ["--replay-mode", "new_conn", "--out", str(RES / "new_conn" / f"output{n}")]) for n in (2, 3)}
    xw = RES / "extra_windows"; ds = xw / "dataset_skip0.json"
    print("== second real window (skip 0) ==")
    x = {n: run_output.main(n, B + ["--dataset", str(ds), "--out", str(xw / f"live_output{n}_skip0")]) for n in (1, 2, 3)}
    print("== offline scoring (no broker involved) ==")
    subprocess.run([sys.executable, "eval/offline_eval.py", "--sensitivity"], cwd=ROOT, stdout=open(RES / "offline_console.txt", "w"))
    subprocess.run([sys.executable, "eval/offline_eval.py", "--dataset", str(ds), "--out", str(xw / "offline_skip0")],
                   cwd=ROOT, stdout=open(xw / "offline_skip0_console.txt", "w"))
    if not a.skip_csv and (ROOT / "external_data" / "replay_attack.csv").exists():
        print("== external CSV (prepare -> 3 outputs -> offline; plus our synthetic DUP=1 variant) ==")
        py = sys.executable
        for cmd in ([py, "prepare_external_replay_csv.py"],
                    [py, "run_external_csv_three_outputs.py", "--broker", a.broker],
                    [py, "eval/csv_offline_eval.py"],
                    [py, "eval/make_csv_dup_variant.py"],
                    [py, "run_external_csv_three_outputs.py", "--broker", a.broker,
                     "--dataset", "external_data/csv_replay_test_ready_dup1.json", "--out-root", "results/csv_external_dup1"],
                    [py, "eval/csv_offline_eval.py", "--dataset", "external_data/csv_replay_test_ready_dup1.json",
                     "--out", "results/csv_external_dup1/offline"]):
            rc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).returncode
            print(f"   {' '.join(Path(c).name for c in cmd[1:3])}: exit {rc}")
    s2 = json.loads((RES / run_output.CFG[2] / "verdict_signature.json").read_text())
    s3 = json.loads((RES / run_output.CFG[3] / "verdict_signature.json").read_text())
    s_off = offline_signature(ROOT / "external_eval" / "fixed_dataset.json")
    eq = {"broker": a.broker, "output2_vs_output3_identical": s2 == s3,
          "live_vs_offline_engine_identical": s2 == s_off,
          "decisions_compared": sum(len(v) for v in s2.values())}
    (RES / "equivalence.json").write_text(json.dumps(eq, indent=2)); print("equivalence:", eq)

    g = lambda d, k: ("n/a" if d.get(k) is None else d.get(k))
    mx = lambda d, k: d["ids_matrix"][k] if "ids_matrix" in d else "n/a"
    mm = lambda d, k: d["ids_metrics"][k] if "ids_metrics" in d else "n/a"
    def table(o, label):
        rows = [("Broker", *(g(o[n], "broker") for n in (1, 2, 3))),
                ("Path", "client -> broker", "client -> IDS -> broker", "client -> IDS (minimize) -> broker"),
                ("Legit PUBLISH sent", *(g(o[n], "legit_sent") for n in (1, 2, 3))),
                ("Legit delivered to subscriber", *(g(o[n], "legit_delivered") for n in (1, 2, 3))),
                ("Legit delivery rate", *(g(o[n], "legit_delivery_rate") for n in (1, 2, 3))),
                ("Replays sent", *(g(o[n], "replay_sent") for n in (1, 2, 3))),
                ("Replays delivered (leaked)", *(g(o[n], "replay_delivered_to_subscriber") for n in (1, 2, 3))),
                ("Replay blocking rate (delivery)", *(g(o[n], "replay_blocking_rate_delivery") for n in (1, 2, 3))),
                ("PUBLISH packets the broker received", *(g(o[n], "broker_received_publishes") for n in (1, 2, 3))),
                ("TP / FP / TN / FN", "n/a (no detector)", *(f"{mx(o[n],'TP')} / {mx(o[n],'FP')} / {mx(o[n],'TN')} / {mx(o[n],'FN')}" for n in (2, 3))),
                ("Precision", "n/a", mm(o[2], "precision"), mm(o[3], "precision")),
                ("Recall", "n/a", mm(o[2], "recall"), mm(o[3], "recall")),
                ("F1", "n/a", mm(o[2], "f1"), mm(o[3], "f1")),
                ("Accuracy", "n/a", mm(o[2], "accuracy"), mm(o[3], "accuracy")),
                ("Delivered payload bytes", *(g(o[n], "delivered_payload_bytes") for n in (1, 2, 3))),
                ("Auth fields (sig/seq/ts) reach app", "yes", "yes", "no"),
                ("Run time (s)", *(g(o[n], "elapsed_s") for n in (1, 2, 3)))]
        return rows
    rows = table(out, "main")
    with (RES / "comparison.csv").open("w", newline="") as f:
        w = csv.writer(f); w.writerow(["metric", "Output 1 No IDS", "Output 2 Layered IDS", "Output 3 Layered IDS + minimized"]); w.writerows(rows)
    md = ["| Metric | Output 1: No IDS | Output 2: Layered IDS | Output 3: Layered IDS + minimized |", "|---|---|---|---|"]
    md += ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]
    (RES / "comparison.md").write_text("\n".join(md) + "\n")
    summ = {"new_conn": {f"output{n}": {k: nc[n][k] for k in ("broker", "replay_delivered_to_subscriber", "ids_matrix", "broker_received_publishes")} for n in nc},
            "skip0_window": {f"output{n}": {k: x[n].get(k) for k in ("broker", "legit_delivered", "replay_delivered_to_subscriber", "ids_matrix", "broker_received_publishes")} for n in x}}
    (RES / "extra_runs_summary.json").write_text(json.dumps(summ, indent=2))
    print("\n".join(md)); print(json.dumps(summ))
    return rc


if __name__ == "__main__":
    sys.exit(main())
