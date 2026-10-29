"""Demonstration consumer for Output 3. Subscribes to the broker and prints ONLY the
application-facing fields (client_id, message, keep_alive). Keep Alive is connection
metadata and comes from the IDS app-feed 'session' records, not from the PUBLISH.
Fails loudly if any verification-only field (sig/hmac/seq/ts) reaches it."""
import argparse, asyncio, json, sys
from .client import MQTTClient
from .minimizer import VERIFICATION_ONLY_KEYS


def load_keepalive(feed):
    ka = {}
    if feed:
        try:
            for line in open(feed, encoding="utf-8"):
                r = json.loads(line)
                if r.get("type") == "session":
                    ka[r["client_id"]] = r["keep_alive"]
        except FileNotFoundError:
            pass
    return ka


async def consume(host, port, topic, count, timeout, feed, out=sys.stdout):
    c = MQTTClient(host, port, "consumer-min", keep_alive=0)
    await c.connect(); await c.subscribe(topic, 1)
    print("[consumer] ready", file=out, flush=True)
    await c.wait_for(lambda: len(c.received) >= count, timeout)
    ka = load_keepalive(feed)
    bad = 0
    for t, payload, *_ in c.received:
        rec = json.loads(payload)
        leak = [k for k in VERIFICATION_ONLY_KEYS if k in rec or k in rec.get("message", {})]
        bad += bool(leak)
        print(json.dumps({"client_id": rec["client_id"], "topic": t, "message": rec["message"],
                          "keep_alive": ka.get(rec["client_id"]), "bytes": len(payload),
                          "verification_fields_leaked": leak}), file=out, flush=True)
    await c.close()
    return len(c.received), bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1"); ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--topic", default="#"); ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--timeout", type=float, default=15); ap.add_argument("--feed")
    a = ap.parse_args()
    n, bad = asyncio.run(consume(a.host, a.port, a.topic, a.count, a.timeout, a.feed))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
