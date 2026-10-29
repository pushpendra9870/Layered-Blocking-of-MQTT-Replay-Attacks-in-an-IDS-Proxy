"""In-process test rig: mini broker + proxy (+ direct subscriber) on free ports."""
import asyncio, os, socket, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from replay_ids.config import Config
from replay_ids.mini_broker import Broker
from replay_ids.proxy import ReplayProxy
from replay_ids.client import MQTTClient
import signing
from replay_ids import mosquitto_runner as mr

# MQTT_TEST_BROKER = mosquitto | mini | auto(default: mosquitto if installed, else mini)
_mode = os.environ.get("MQTT_TEST_BROKER", "auto")
BROKER = ("mosquitto" if mr.find_mosquitto() else "mini") if _mode == "auto" else _mode


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def signed(topic, data, seq, ts="1.0"):
    return signing.build_signed_payload(topic, data, seq, ts)


class Rig:
    """minimize / use_proxy select Output 3 / Output 2 / Output 1."""
    def __init__(self, use_proxy=True, minimize=False, **cfg_over):
        self.use_proxy, self.minimize, self.over = use_proxy, minimize, cfg_over
        self.tasks = []

    async def __aenter__(self):
        self.bport, self.pport = free_port(), free_port()
        self.proc = None
        if BROKER == "mosquitto":
            self.tmp = tempfile.TemporaryDirectory()
            self.log_path = Path(self.tmp.name) / "mosquitto.log"
            self.proc = mr.start(self.bport, self.tmp.name, self.log_path)   # fresh broker per test
            self.broker = None
        else:
            self.broker = Broker("127.0.0.1", self.bport)
            self.tasks.append(await asyncio.start_server(self.broker.handle, "127.0.0.1", self.bport))
        self.cfg = Config(listen_port=self.pport, broker_port=self.bport, minimize=self.minimize,
                          console=False, **self.over)
        if self.use_proxy:
            self.proxy = ReplayProxy(self.cfg)
            self.tasks.append(await asyncio.start_server(self.proxy.handle, "127.0.0.1", self.pport))
            self.log = self.proxy.log
            self.log.records = []
        self.target = self.pport if self.use_proxy else self.bport
        self.clients = []
        self.sub = await self.client("observer", port=self.bport)     # direct to broker
        await self.sub.subscribe("#", 1)
        return self

    async def client(self, cid, clean=True, port=None, **kw):
        c = MQTTClient("127.0.0.1", port or self.target, cid, clean=clean, **kw)
        await c.connect(); self.clients.append(c); return c

    def broker_received(self):
        """PUBLISH packets the BROKER itself received (Mosquitto log / mini-broker counter)."""
        if self.proc is not None:
            return mr.count_publishes(self.log_path)
        return self.broker.received

    def delivered(self):
        return [(t, p) for t, p, *_ in self.sub.received]

    def decisions(self):
        return [r for r in self.log.records if r.get("event") == "decision"]

    async def settle(self, t=0.25):
        await asyncio.sleep(t + (0.15 if self.proc is not None else 0))

    async def __aexit__(self, *a):
        for c in self.clients:
            await c.close(send_disconnect=False)
        for s in self.tasks:
            s.close()
        if self.proc is not None:
            self.proc.terminate()
            try: self.proc.wait(5)
            except Exception: self.proc.kill()
            try: self.tmp.cleanup()
            except Exception: pass
