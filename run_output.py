"""Orchestrates ONE configuration end to end (starts broker [+ proxy], runs the live
evaluation on the real dataset, stops everything). Used by the three entry points."""
import argparse, json, socket, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
CFG = {1: "output1_no_ids", 2: "output2_layered_ids", 3: "output3_layered_ids_minimized"}


def wait_port(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close(); return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"port {port} did not open")


def stop(p):
    if p and p.poll() is None:
        p.terminate()
        try: p.wait(5)
        except subprocess.TimeoutExpired: p.kill()


def main(n, argv=None):
    ap = argparse.ArgumentParser(description=f"Run {CFG[n]}")
    ap.add_argument("--replay-mode", default="same_conn", choices=["same_conn", "new_conn"])
    ap.add_argument("--broker", default="mosquitto", choices=["mosquitto", "mini", "external"],
                    help="mosquitto (default): this script starts a private Mosquitto; mini: bundled "
                         "test broker; external: an already-running broker on --broker-port")
    ap.add_argument("--broker-port", type=int, default=18830)
    ap.add_argument("--proxy-port", type=int, default=18840)
    ap.add_argument("--out", default=None)
    ap.add_argument("--dataset", default=str(ROOT / "external_eval" / "fixed_dataset.json"))
    a = ap.parse_args(argv)
    name = CFG[n]
    out = Path(a.out or ROOT / "results" / name); out.mkdir(parents=True, exist_ok=True)
    py, procs = sys.executable, []
    broker_log = out / ("mosquitto.log" if a.broker == "mosquitto" else "broker_publish_log.jsonl")
    try:
        if a.broker == "mosquitto":
            from replay_ids import mosquitto_runner as mr
            exe = mr.find_mosquitto()
            (out / "broker.txt").write_text(f"broker=mosquitto\n{mr.version(exe) if exe else 'NOT FOUND'}\n{exe}\n")
            procs.append(mr.start(a.broker_port, out, broker_log))
        elif a.broker == "mini":
            (out / "broker.txt").write_text("broker=mini_broker (bundled test broker)\n")
            procs.append(subprocess.Popen([py, "-m", "replay_ids.mini_broker", "--port", str(a.broker_port),
                                           "--log", str(broker_log)], cwd=ROOT))
        wait_port(a.broker_port)
        target = a.broker_port
        dec_log = None
        if n in (2, 3):
            dec_log = out / "decisions.jsonl"
            cmd = [py, "-m", "replay_ids.proxy", "--config", str(ROOT / "configs" / f"{name}.json"),
                   "--listen-port", str(a.proxy_port), "--broker-port", str(a.broker_port),
                   "--decision-log", str(dec_log)]
            if n == 3:
                cmd += ["--app-feed", str(out / "app_feed.jsonl")]
            procs.append(subprocess.Popen(cmd, cwd=ROOT, stdout=open(out / "proxy_console.log", "w")))
            wait_port(a.proxy_port)
            target = a.proxy_port
        from eval import live_eval
        args = ["--name", name, "--target-port", str(target), "--broker-port", str(a.broker_port),
                "--replay-mode", a.replay_mode, "--out", str(out), "--dataset", a.dataset]
        if a.broker in ("mini", "mosquitto"):
            args += ["--broker-log", str(broker_log)]
        if dec_log:
            args += ["--decision-log", str(dec_log)]
        res = live_eval.main(args)
        if n == 3:
            from eval.consumer_demo import run_demo
            run_demo(a.broker_port, a.proxy_port, out)
        return res
    finally:
        for p in reversed(procs):
            stop(p)
