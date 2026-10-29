"""Workload driver for the performance benchmark. Uses the EXISTING dataset
(external_eval/fixed_dataset.json) through eval.live_eval.load/msg_key/send_batch.
  saturation : K rounds x 14 connections (fresh client-ids per round), pipelined, no pacing
  paced      : one round, global fixed offered rate (latency without queueing collapse)"""
import asyncio, collections, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from replay_ids.client import MQTTClient
from eval.live_eval import load, msg_key, send_batch

pc = time.perf_counter


async def drive(target_port, broker_port, dataset, mode, rounds=1, rate=400.0, timeout=180,
                hook_start=lambda: None, hook_end=lambda: None):
    recs, per = load(dataset)
    obs = MQTTClient("127.0.0.1", broker_port, "observer-direct", keep_alive=0)
    await obs.connect(); await obs.subscribe("#", 1)
    clients = []                                   # (client, group, key)
    for k in range(rounds):
        for key, g in per.items():
            c = MQTTClient("127.0.0.1", target_port, f"dev-{key[1]}-r{k}", clean=True, keep_alive=0)
            await c.connect(); clients.append((c, g, key))
    out = {"mode": mode, "rounds": rounds}
    legit_total = sum(len(g["legit"]) for _, g, _ in clients)
    replay_total = sum(len(g["replay"]) for _, g, _ in clients)
    sent_at, key_sent = {}, collections.defaultdict(collections.deque)
    hook_start(); t0 = pc()
    if mode == "saturation":
        ok1 = await asyncio.gather(*[send_batch(c, g["legit"], timeout) for c, g, _ in clients])
        t_legit = pc()
        ok2 = await asyncio.gather(*[send_batch(c, g["replay"], timeout) for c, g, _ in clients if g["replay"]])
        t_all = pc()
        ok = all(ok1) and all(ok2)
    else:
        order = []                                  # dataset order, round 0 only
        idx = {key: (c, g) for c, g, key in clients[:len(per)]}
        for r in recs:
            if r["truth"] == "legit":
                p = r["packet"]; order.append((idx[(p["src_ip"], p["src_port"])][0], p))
        for i, (c, p) in enumerate(order):
            delay = t0 + i / rate - pc()
            if delay > 0:
                await asyncio.sleep(delay)
            now = pc()
            sent_at[(id(c), p["packet_id"])] = now
            payload = bytes.fromhex(p["payload_hex"])
            key_sent[msg_key(p["topic"], payload)].append(now)
            c.publish_nowait(p["topic"], payload, p["qos"], p["packet_id"], p["dup"])
            await c.writer.drain()
        t_send_done = pc()
        for c, g, _ in clients[:len(per)]:
            await c.wait_for(lambda c=c, n=len([1 for cc, p in order if cc is c]): len(c.completed) >= n, timeout)
        t_legit = pc()
        ok2 = await asyncio.gather(*[send_batch(c, g["replay"], timeout) for c, g, _ in clients[:len(per)] if g["replay"]])
        t_all = pc(); ok = all(ok2)
        out["achieved_offered_rate"] = len(order) / (t_send_done - t0)
        rtt = []
        for c, g, _ in clients[:len(per)]:
            seen = set()
            for pid, t in c.ack_log:
                if pid not in seen and (id(c), pid) in sent_at:
                    seen.add(pid); rtt.append(t - sent_at[(id(c), pid)])
        out["ack_rtt_s"] = rtt
    hook_end()
    last, stable = -1, 0
    for _ in range(150):
        n = len(obs.received); stable = stable + 1 if n == last else 0; last = n
        if stable >= 6: break
        await asyncio.sleep(0.1)
    if mode == "paced":
        e2e = []
        for topic, payload, t in obs.recv_log:
            q = key_sent.get(msg_key(topic, payload))
            if q:
                e2e.append(t - q.popleft())
        out["e2e_s"] = e2e
    L = collections.Counter(); R = collections.Counter(); D = collections.Counter()
    for c, g, _ in clients:
        for r in g["legit"]:
            L[msg_key(r["packet"]["topic"], bytes.fromhex(r["packet"]["payload_hex"]))] += 1
        for r in g["replay"]:
            R[msg_key(r["packet"]["topic"], bytes.fromhex(r["packet"]["payload_hex"]))] += 1
    for t, p, *_ in obs.received:
        D[msg_key(t, p)] += 1
    keys = set(L) | set(R) | set(D)
    out.update(legit_sent=legit_total, replay_sent=replay_total, delivered=len(obs.received),
               replay_leaked=sum(max(0, D[k] - L[k]) for k in keys),
               legit_lost=sum(max(0, L[k] - D[k]) for k in keys),
               all_acked=ok, t_total_s=t_all - t0, t_legit_phase_s=t_legit - t0,
               client_tx_bytes=sum(c.tx_bytes for c, _, _ in clients),
               client_rx_bytes=sum(c.rx_bytes for c, _, _ in clients),
               observer_rx_bytes=obs.rx_bytes,
               observer_payload_bytes=sum(len(p) for _, p, *_ in obs.received))
    for c, _, _ in clients:
        await c.close()
    await obs.close()
    return out
