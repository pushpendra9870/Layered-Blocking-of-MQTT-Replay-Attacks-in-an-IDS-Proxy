"""Scripted scenario matrix: the SAME packet sequences are sent in all three configurations
against a fresh private Mosquitto (debug log on). Ground truth for 'reached the broker' is
Mosquitto's own log. All traffic here is SYNTHETIC (signed with the project key).
ideal = number of PUBLISH packets that SHOULD reach the broker under perfect replay filtering."""
import asyncio, json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tests.harness import Rig, signed
from replay_ids import codec
from replay_ids.client import MQTTClient

T = "scn/t"
S = lambda seq, d=None, ts="1.0": signed(T, d if d is not None else {"v": seq}, seq, ts)
P = lambda pid, seq, qos=1, dup=False, payload=None: codec.build_publish(T, pid, payload if payload is not None else S(seq), qos, dup)


async def acked(c, n, t=5):
    await c.wait_for(lambda: len(c.completed) >= n, t)


async def s1(r):
    c = await r.client("devA")
    for i in range(1, 6):
        c.send_raw(P(i, i)); await c.writer.drain()
    await acked(c, 5); return dict(legit=5, attack=0, ideal=5)

async def s2(r):
    c = await r.client("devA")
    c.send_raw(P(1, 1) + P(1, 1, dup=True)); await c.writer.drain()          # one coalesced write
    await acked(c, 2); return dict(legit=2, attack=0, ideal=2)

async def s3(r):
    c = await r.client("devA")
    for i in range(1, 4):
        c.send_raw(P(i, i, qos=2)); await c.writer.drain(); await c.wait_for(lambda i=i: len(c.completed) >= i, 5)
    return dict(legit=3, attack=0, ideal=3)

async def s4(r):
    c = await r.client("devA")
    for i in range(1, 4):
        c.send_raw(P(9, i)); await c.writer.drain(); await c.wait_for(lambda i=i: len(c.completed) >= i, 5)
    return dict(legit=3, attack=0, ideal=3)

async def s5(r):
    c = await r.client("devA"); c.send_raw(P(1, 1)); await c.writer.drain(); await acked(c, 1)
    for _ in range(3):
        c.send_raw(P(1, 1)); await c.writer.drain()
    await acked(c, 4); return dict(legit=1, attack=3, ideal=1)

async def s6(r):
    c = await r.client("devA"); c.send_raw(P(1, 1)); await c.writer.drain(); await acked(c, 1)
    for _ in range(3):
        c.send_raw(P(1, 1, dup=True)); await c.writer.drain()
    await acked(c, 4); return dict(legit=1, attack=3, ideal=1)

async def s7(r):
    c = await r.client("devA"); n = 0
    for i in range(1, 301):
        if i == 3: continue
        c.send_raw(P((i % 60000) + 1, i)); n += 1
        if i % 50 == 0: await c.writer.drain()
    await c.writer.drain(); await acked(c, n, 20)
    c.send_raw(P(7000, 3, dup=True)); await c.writer.drain(); await acked(c, n + 1)
    return dict(legit=n, attack=1, ideal=n)

async def s8(r):
    c = await r.client("devA")
    for i in range(1, 4):
        c.send_raw(P(i, i, payload=S(i).replace(b'"v": %d' % i, b'"v": 99'))); await c.writer.drain()
    await acked(c, 3); return dict(legit=0, attack=3, ideal=0)

async def s9(r):
    c = await r.client("devA")
    for i in range(1, 4):
        c.send_raw(P(i, i, payload=b"unsigned-%d" % i)); await c.writer.drain()
    await acked(c, 3); return dict(legit=0, attack=3, ideal=0)

async def s10(r):
    c = await r.client("devA"); c.send_raw(P(1, 1)); await c.writer.drain(); await acked(c, 1); await c.close()
    c2 = await r.client("devA")                                              # clean session
    for _ in range(2):
        c2.send_raw(P(1, 1)); await c2.writer.drain()
    await acked(c2, 2); return dict(legit=1, attack=2, ideal=1)

async def s11(r):
    c = await r.client("devA", clean=False); c.send_raw(P(1, 1)); await c.writer.drain(); await acked(c, 1)
    await c.close(send_disconnect=False)
    c2 = await r.client("devA", clean=False)
    c2.send_raw(P(2, 2)); await c2.writer.drain(); await acked(c2, 1)
    c2.send_raw(P(1, 1, dup=True)); await c2.writer.drain(); await acked(c2, 2)
    return dict(legit=2, attack=1, ideal=2)

async def s12(r):
    c = await r.client("devA", clean=False); c.send_raw(P(1, 1)); await c.writer.drain(); await acked(c, 1)
    await c.close(send_disconnect=False)
    c2 = await r.client("devA", clean=False)
    c2.send_raw(P(1, 1, dup=True)); await c2.writer.drain(); await acked(c2, 1)   # lost-ACK retransmission
    return dict(legit=2, attack=0, ideal=2)

async def s13(r):                                                           # cross-identity replay
    a = await r.client("devA"); a.send_raw(P(1, 1)); await a.writer.drain(); await acked(a, 1)
    b = await r.client("devB"); b.send_raw(P(1, 1)); await b.writer.drain(); await acked(b, 1)   # same bytes, other client-id
    return dict(legit=1, attack=1, ideal=1)

SCEN = [("S1", "Legit QoS1, fresh seq", "legit", s1), ("S2", "Legit QoS1 DUP retransmission (in flight)", "retx", s2),
        ("S3", "Legit QoS2 full handshake", "legit", s3), ("S4", "Packet-ID reuse after completion, fresh seq", "legit", s4),
        ("S5", "Exact replay (DUP=0)", "attack", s5), ("S6", "DUP-evasion replay (DUP=1, ACKed id)", "attack", s6),
        ("S7", "Stale-sequence replay (beyond window)", "attack", s7), ("S8", "Invalid HMAC (tampered)", "attack", s8),
        ("S9", "Missing signature", "attack", s9), ("S10", "Replay after clean-session reconnect", "attack", s10),
        ("S11", "Replay after persistent-session resume", "attack", s11), ("S12", "Lost-ACK retransmit after resume", "uncertain", s12),
        ("S13", "Cross-identity replay (captured from devA, sent as devB)", "attack", s13)]
NAMES = {1: "No IDS", 2: "IDS full packet", 3: "Modified IDS"}


async def run_one(fn, cfg):
    async with Rig(use_proxy=cfg > 1, minimize=(cfg == 3)) as r:
        if cfg == 3:
            from replay_ids.minimizer import AppFeed
            r.proxy.feed = AppFeed("")
        info = await fn(r)
        await r.settle(0.5)
        info["broker_received"] = r.broker_received()
        info["delivered"] = len(r.delivered())
        if cfg > 1:
            info["decisions"] = [(d["classification"], d["reason"], d["action"]) for d in r.decisions()]
        return info


def main(out=ROOT / "results" / "bench" / "scenario_matrix.json"):
    rows = []
    for sid, name, kind, fn in SCEN:
        for cfg in (1, 2, 3):
            info = asyncio.run(run_one(fn, cfg))
            info.update(id=sid, scenario=name, kind=kind, config=cfg, label=NAMES[cfg],
                        attack_leaked=max(0, info["broker_received"] - info["ideal"]),
                        legit_lost=max(0, info["ideal"] - info["broker_received"]))
            rows.append(info)
            print(f"{sid:3s} cfg{cfg} sent legit={info['legit']:>3} attack={info['attack']} ideal={info['ideal']:>3} "
                  f"broker={info['broker_received']:>3} leaked={info['attack_leaked']} lost={info['legit_lost']}", flush=True)
    Path(out).write_text(json.dumps(rows, indent=1, default=str))


if __name__ == "__main__":
    main()
