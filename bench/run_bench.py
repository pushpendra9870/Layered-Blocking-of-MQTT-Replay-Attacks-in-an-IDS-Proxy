"""Performance benchmark of the three configurations on the SAME real dataset.
Measures: throughput, latency, CPU time and RSS of the broker and the IDS proxy, bytes on the wire.
Usage: python -m bench.run_bench --reps 5 --scale 10 --rate 400"""
import argparse, asyncio, json, os, socket, statistics, subprocess, sys, tempfile, threading, time
from pathlib import Path
import psutil
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from replay_ids import mosquitto_runner as mr
from bench.driver import drive

CFG = {1: "output1_no_ids", 2: "output2_layered_ids", 3: "output3_layered_ids_minimized"}
LABEL = {1: "No IDS", 2: "IDS full packet", 3: "Modified IDS"}


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Monitor:
    """CPU seconds (user+sys) and RSS (sampled every 20 ms) for the processes UNDER TEST only."""
    def __init__(self, pids):
        self.procs = {n: psutil.Process(p) for n, p in pids.items()}
        self.peak = {n: 0 for n in pids}; self.base = {}; self.cpu0 = {}; self.cpu1 = {}
        self._run = False

    def _ct(self, p):
        t = p.cpu_times(); return t.user + t.system

    def start(self):
        for n, p in self.procs.items():
            self.base[n] = p.memory_info().rss; self.cpu0[n] = self._ct(p); self.peak[n] = self.base[n]
        self._run = True; self.t0 = time.perf_counter()
        self.th = threading.Thread(target=self._loop, daemon=True); self.th.start()

    def _loop(self):
        while self._run:
            for n, p in self.procs.items():
                try: self.peak[n] = max(self.peak[n], p.memory_info().rss)
                except psutil.Error: pass
            time.sleep(0.02)

    def stop(self):
        self._run = False; self.th.join(1); self.wall = time.perf_counter() - self.t0
        for n, p in self.procs.items():
            self.cpu1[n] = self._ct(p); self.end_rss = {m: q.memory_info().rss for m, q in self.procs.items()}

    def result(self):
        r = {}
        for n in self.procs:
            r[n] = {"cpu_s": self.cpu1[n] - self.cpu0[n], "rss_base_mb": self.base[n] / 2**20,
                    "rss_peak_mb": self.peak[n] / 2**20, "rss_end_mb": self.end_rss[n] / 2**20}
        return r


def run_one(n, mode, dataset, rounds, rate):
    tmp = tempfile.TemporaryDirectory(); T = Path(tmp.name)
    bport, pport = free_port(), free_port()
    broker = mr.start(bport, T, T / "mosq.log", debug=False)         # quiet broker for performance runs
    proxy, stats = None, T / "stats.json"
    try:
        if n > 1:
            cmd = [sys.executable, "-m", "replay_ids.proxy", "--config", str(ROOT / "configs" / f"{CFG[n]}.json"),
                   "--listen-port", str(pport), "--broker-port", str(bport),
                   "--decision-log", str(T / "decisions.jsonl"), "--stats", str(stats)]
            if n == 3:
                cmd += ["--app-feed", str(T / "feed.jsonl")]
            proxy = subprocess.Popen(cmd, cwd=ROOT, stdout=open(T / "proxy.out", "w"), stderr=subprocess.STDOUT)
            end = time.time() + 10
            while time.time() < end:
                try: socket.create_connection(("127.0.0.1", pport), 0.3).close(); break
                except OSError: time.sleep(0.1)
        pids = {"broker": broker.pid}
        if proxy: pids["proxy"] = proxy.pid
        mon = Monitor(pids)
        res = asyncio.run(drive(pport if n > 1 else bport, bport, dataset, mode, rounds, rate,
                                hook_start=mon.start, hook_end=mon.stop))
        res["resources"] = mon.result(); res["monitor_wall_s"] = mon.wall
        if proxy:
            time.sleep(1.3)
            res["proxy_stats"] = json.loads(stats.read_text())
            dec = [json.loads(l) for l in open(T / "decisions.jsonl") if '"decision"' in l]
            res["n_decisions"] = len(dec)
        return res
    finally:
        for p in (proxy, broker):
            if p and p.poll() is None:
                p.terminate()
                try: p.wait(5)
                except Exception: p.kill()
        tmp.cleanup()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5); ap.add_argument("--scale", type=int, default=10)
    ap.add_argument("--rate", type=float, default=400.0)
    ap.add_argument("--dataset", default=str(ROOT / "external_eval" / "fixed_dataset.json"))
    ap.add_argument("--out", default=str(ROOT / "results" / "bench"))
    ap.add_argument("--modes", default="saturation,paced")
    ap.add_argument("--resume", action="store_true", help="skip (mode,rep,config) already in raw_runs.jsonl")
    ap.add_argument("--max-runs", type=int, default=10**9, help="stop after N new runs (for time-boxed sessions)")
    a = ap.parse_args()
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    exe = mr.find_mosquitto()
    meta = {"python": sys.version.split()[0], "mosquitto": mr.version(exe), "cpus": os.cpu_count(),
            "psutil": psutil.__version__, "reps": a.reps, "scale": a.scale, "rate": a.rate,
            "mem_total_mb": psutil.virtual_memory().total / 2**20, "platform": sys.platform}
    runs = []
    raw = out / "raw_runs.jsonl"
    done = set()
    if a.resume and raw.exists():
        for l in raw.read_text().splitlines():
            if l.strip():
                d = json.loads(l); done.add((d["mode"], d["rep"], d["config"]))
    else:
        raw.write_text("")
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    orders = [[1, 2, 3], [2, 3, 1], [3, 1, 2]]
    new = 0
    for mode in a.modes.split(","):
        rounds = a.scale if mode == "saturation" else 1
        if not any(k[0] == mode for k in done):
            for n in (1, 2, 3):                                       # warm-up, discarded
                run_one(n, mode, a.dataset, 1, a.rate)
        for rep in range(a.reps):
            for n in orders[rep % 3]:                                 # rotated order cancels drift
                if (mode, rep, n) in done:
                    continue
                if new >= a.max_runs:
                    print("max-runs reached; re-run with --resume to continue"); return
                new += 1
                r = run_one(n, mode, a.dataset, rounds, a.rate)
                r.update(config=n, label=LABEL[n], rep=rep, mode=mode)
                runs.append(r)
                with raw.open("a") as f:
                    f.write(json.dumps(r) + "\n")
                print(f"[{mode} rep{rep}] cfg{n}: total={r['t_total_s']:.2f}s delivered={r['delivered']} "
                      f"leaked={r['replay_leaked']} lost={r['legit_lost']}", flush=True)
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    print("done ->", out)


if __name__ == "__main__":
    main()
