"""Output 3 demo: a separate consumer process sees only minimized records."""
import asyncio, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from replay_ids.client import MQTTClient
import signing


def run_demo(broker_port, proxy_port, out):
    out = Path(out)
    log = open(out / "consumer_demo.txt", "w", encoding="utf-8")
    cons = subprocess.Popen([sys.executable, "-m", "replay_ids.consumer_min", "--port", str(broker_port),
                             "--topic", "demo/#", "--count", "3", "--timeout", "10",
                             "--feed", str(out / "app_feed.jsonl")], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    time.sleep(1.0)

    async def send():
        c = MQTTClient("127.0.0.1", proxy_port, "demo-device-1", keep_alive=30)
        await c.connect()
        for i in (1, 2, 3):
            t = f"demo/room{i}"
            await c.publish(t, signing.build_signed_payload(t, {"temp_c": 20 + i}, i, f"{time.time():.3f}"), 1, pid=i)
        await c.wait_for(lambda: len(c.completed) == 3)
        await c.publish("demo/room1", signing.build_signed_payload("demo/room1", {"temp_c": 21}, 1, "x"), 1, pid=1)  # replay
        await asyncio.sleep(0.3)
        await c.close()
    asyncio.run(send())
    rc = cons.wait(20); log.close()
    print(f"[consumer demo] exit={rc} (0 = no verification-only field leaked) -> {out/'consumer_demo.txt'}")
