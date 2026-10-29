"""Live evaluation: replays the EXISTING external_eval/fixed_dataset.json over real TCP.

  legit records  = real captured PUBLISHes (re-signed by prepare_dataset.py)
  replay records = synthetic attacker copies made by attacker_replay.py
  dataset PUBACKs are NOT replayed: the live broker generates its own.
  Each original (src_ip,src_port) connection becomes a client 'dev-<port>' (the capture has no
  CONNECT/client-id; this wrapper is synthetic).

Two independent measurements:
  * IDS verdicts  : from the proxy decision log (Outputs 2/3)
  * actual delivery: a subscriber connected DIRECTLY to the broker (+ broker's own PUBLISH log)
"""
import argparse, asyncio, collections, csv, json, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from replay_ids import _legacy  # noqa
from replay_ids.client import MQTTClient
import score as legacy_score


def load(dataset, limit=None):
    recs = [r for r in json.loads(Path(dataset).read_text()) if r["scored"]]
    per = collections.OrderedDict()
    for r in recs:
        p = r["packet"]
        per.setdefault((p["src_ip"], p["src_port"]), {"legit": [], "replay": []})[r["truth"]].append(r)
    return recs, per


def msg_key(topic, payload):
    """(topic, device message) for signed OR minimized payloads."""
    try:
        o = json.loads(payload)
        m = o["data"] if "sig" in o else o["message"]
        return topic, json.dumps(m, sort_keys=True)
    except Exception:
        return topic, payload.hex()


async def send_batch(c, recs, timeout):
    base = len(c.completed)
    for i, r in enumerate(recs):
        p = r["packet"]
        c.publish_nowait(p["topic"], bytes.fromhex(p["payload_hex"]), p["qos"], p["packet_id"], p["dup"])
        if i % 100 == 99:
            await c.writer.drain()
    await c.writer.drain()
    ok = await c.wait_for(lambda: len(c.completed) - base >= len(recs), timeout)
    return ok


async def run(a):
    recs, per = load(a.dataset)
    t0 = time.time()
    obs = MQTTClient("127.0.0.1", a.broker_port, "observer-direct", keep_alive=0)
    await obs.connect(); await obs.subscribe("#", 1)

    clients, send_ok = {}, True
    async def legit_phase(key, groups):
        c = MQTTClient("127.0.0.1", a.target_port, f"dev-{key[1]}", clean=True, keep_alive=0)
        await c.connect(); clients[key] = c
        return await send_batch(c, groups["legit"], a.timeout)
    res = await asyncio.gather(*[legit_phase(k, g) for k, g in per.items()])
    send_ok &= all(res)
    t_legit = time.time()

    async def replay_phase(key, groups):
        if not groups["replay"]:
            return True
        c = clients[key]
        if a.replay_mode == "new_conn":              # attacker reconnects with the victim's client-id
            await c.close(send_disconnect=True)
            c = MQTTClient("127.0.0.1", a.target_port, f"dev-{key[1]}", clean=True, keep_alive=0)
            await c.connect(); clients[key] = c
        return await send_batch(c, groups["replay"], a.timeout)
    res = await asyncio.gather(*[replay_phase(k, g) for k, g in per.items()])
    send_ok &= all(res)

    last, stable = -1, 0                                # wait for delivery to quiesce
    for _ in range(100):
        n = len(obs.received)
        stable = stable + 1 if n == last else 0
        last = n
        if stable >= 6:
            break
        await asyncio.sleep(0.1)
    t_end = time.time()
    for c in clients.values():
        await c.close()
    await obs.close()
    return recs, per, obs.received, send_ok, t_end - t0


def analyse(a, recs, per, delivered, send_ok, elapsed):
    legit = [r for r in recs if r["truth"] == "legit"]
    replay = [r for r in recs if r["truth"] == "replay"]
    L = collections.Counter(msg_key(r["packet"]["topic"], bytes.fromhex(r["packet"]["payload_hex"]))
                            for r in legit)
    R = collections.Counter(msg_key(r["packet"]["topic"], bytes.fromhex(r["packet"]["payload_hex"]))
                            for r in replay)
    D = collections.Counter(msg_key(t, p) for t, p, *_ in delivered)
    keys = set(L) | set(R) | set(D)
    leaked = sum(max(0, D[k] - L[k]) for k in keys)
    legit_missing = sum(max(0, L[k] - D[k]) for k in keys)
    out = {
        "output": a.name, "replay_mode": a.replay_mode, "elapsed_s": round(elapsed, 2),
        "all_sends_acknowledged": send_ok,
        "legit_sent": len(legit), "replay_sent": len(replay),
        "delivered_total": len(delivered),
        "delivered_payload_bytes": sum(len(p) for _, p, *_ in delivered),
        "legit_delivered": len(legit) - legit_missing,
        "legit_delivery_rate": round((len(legit) - legit_missing) / len(legit), 4),
        "legit_lost": legit_missing,
        "replay_delivered_to_subscriber": leaked,
        "replay_blocking_rate_delivery": round(1 - leaked / len(replay), 4) if replay else None,
        "delivery_attribution": "per-(topic,message) counts; assumes a leaked replay is not masked "
                                "by a lost legit packet on the same key (cross-checked vs IDS log)",
    }
    if a.broker_log and Path(a.broker_log).exists():
        if str(a.broker_log).endswith(".log"):          # Mosquitto debug log
            time.sleep(0.5)
            from replay_ids import mosquitto_runner as mr
            out["broker_received_publishes"] = mr.count_publishes(a.broker_log, "dev-")
            out["broker"] = "mosquitto"
        else:                                           # bundled mini broker JSONL
            lines = [json.loads(l) for l in open(a.broker_log) if l.strip()]
            out["broker_received_publishes"] = len([l for l in lines if l["client_id"].startswith("dev-")])
            out["broker"] = "mini_broker"
    if a.decision_log and Path(a.decision_log).exists():
        dec = [json.loads(l) for l in open(a.decision_log) if l.strip()]
        dec = [d for d in dec if d.get("event") == "decision"]
        by_client = collections.defaultdict(list)
        for d in dec:
            by_client[d["client_id"]].append(d)
        m = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        kinds = collections.defaultdict(lambda: {"total": 0, "dropped": 0})
        reasons = collections.Counter()
        sig = {}
        aligned = True
        for key, g in per.items():
            seq_recs = g["legit"] + g["replay"]
            ds = by_client.get(f"dev-{key[1]}", [])
            if len(ds) != len(seq_recs):
                aligned = False
            for r, d in zip(seq_recs, ds):
                pred = d["action"] == "drop"
                isr = r["truth"] == "replay"
                m["TP" if isr and pred else "FN" if isr else "FP" if pred else "TN"] += 1
                kinds[r["kind"]]["total"] += 1; kinds[r["kind"]]["dropped"] += pred
                reasons[(d["classification"], d["reason"], d["action"], d["detector"])] += 1
            sig[f"dev-{key[1]}"] = [(d["classification"], d["reason"], d["action"], d["detector"]) for d in ds]
        out["ids_verdict_aligned_with_dataset"] = aligned
        out["ids_matrix"] = m
        out["ids_metrics"] = {k: round(v, 4) for k, v in legacy_score.metrics(m).items()}
        out["ids_by_kind"] = dict(kinds)
        out["ids_reason_breakdown"] = {"|".join(k): v for k, v in reasons.items()}
        out["ids_replays_dropped"] = m["TP"]
        out["replay_blocking_rate_ids"] = round(m["TP"] / len(replay), 4) if replay else None
        out["_signature"] = sig
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--dataset", default=str(ROOT / "external_eval" / "fixed_dataset.json"))
    ap.add_argument("--target-port", type=int, required=True, help="port clients connect to")
    ap.add_argument("--broker-port", type=int, required=True, help="direct broker port (observer)")
    ap.add_argument("--broker-log"); ap.add_argument("--decision-log")
    ap.add_argument("--replay-mode", choices=["same_conn", "new_conn"], default="same_conn")
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    recs, per, delivered, ok, el = asyncio.run(run(a))
    res = analyse(a, recs, per, delivered, ok, el)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    sig = res.pop("_signature", None)
    if sig is not None:
        (out / "verdict_signature.json").write_text(json.dumps(sig))
    (out / "live_results.json").write_text(json.dumps(res, indent=2))
    print(json.dumps({k: v for k, v in res.items() if k not in ("ids_by_kind", "ids_reason_breakdown",
                                                                  "delivery_attribution")}, indent=2))
    return res


if __name__ == "__main__":
    main()
