"""Replay-IDS TCP proxy:  client -> [this proxy] -> broker.

* Both directions are parsed with a stream framer (MQTT 3.1/3.1.1).
* client->broker PUBLISH goes through the layered engine; confirmed replays are
  really dropped (never written to the broker socket).
* broker->client traffic (CONNACK, PUBACK/PUBREC/PUBCOMP, SUBACK, PINGRESP and
  PUBLISH to subscribers) is relayed untouched; ack packets also update
  transaction state *before* being relayed.
* Keep-alive, QoS handshakes, sessions and reconnects are the broker's; the proxy
  adds no timers of its own.
* Output 3 (cfg.minimize): after verification the forwarded PUBLISH payload is
  replaced by {client_id, message}; the wire packet stays a valid PUBLISH.
"""
import argparse, asyncio, itertools, json, sys, time

from . import codec
from .config import Config
from .decisionlog import DecisionLog
from .engine import LayeredReplayEngine, DROP
from .minimizer import AppFeed, minimized_payload


class ReplayProxy:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.log = DecisionLog(cfg.decision_log, cfg.console, keep=False, output=cfg.name)
        self.engine = LayeredReplayEngine(cfg, self.log)
        self.feed = AppFeed(cfg.app_feed) if cfg.minimize else None
        self._ids = itertools.count(1)
        self.counters = {"c2b_packets": 0, "b2c_packets": 0, "dropped": 0, "forwarded_publish": 0,
                         "bytes_publish_in": 0, "bytes_publish_out": 0,
                         "bytes_from_clients": 0, "bytes_to_broker": 0, "bytes_from_broker": 0,
                         "bytes_to_clients_relayed": 0, "bytes_to_clients_synthetic": 0,
                         "synthetic_acks": 0}
        self.t_decide, self.t_handle = [], []        # seconds per PUBLISH (measurement only)

    def _wb(self, bw, data):
        self.counters["bytes_to_broker"] += len(data); bw.write(data)

    def _wc(self, cw, data, synthetic=False):
        self.counters["bytes_to_clients_synthetic" if synthetic else "bytes_to_clients_relayed"] += len(data)
        if synthetic:
            self.counters["synthetic_acks"] += 1
        cw.write(data)

    @staticmethod
    def _pct(xs):
        if not xs:
            return {}
        s = sorted(xs); n = len(s)
        q = lambda f: s[min(n - 1, int(f * n))]
        return {"n": n, "mean_us": 1e6 * sum(s) / n, "p50_us": 1e6 * q(.5), "p95_us": 1e6 * q(.95),
                "p99_us": 1e6 * q(.99), "max_us": 1e6 * s[-1]}

    def dump_stats(self):
        if not self.cfg.stats_path:
            return
        d = {"counters": dict(self.counters), "decision_time": self._pct(self.t_decide),
             "handling_time": self._pct(self.t_handle), "decisions": {"|".join(k): v for k, v in self.engine.stats.items()}}
        tmp = self.cfg.stats_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        import os; os.replace(tmp, self.cfg.stats_path)

    async def _stats_loop(self):
        while True:
            await asyncio.sleep(1.0)
            self.dump_stats()

    async def serve(self):
        if self.cfg.stats_path:
            asyncio.create_task(self._stats_loop())
        srv = await asyncio.start_server(self.handle, self.cfg.listen_host, self.cfg.listen_port)
        print(f"[proxy:{self.cfg.name}] {self.cfg.listen_host}:{self.cfg.listen_port} -> "
              f"{self.cfg.broker_host}:{self.cfg.broker_port} "
              f"minimize={self.cfg.minimize}", flush=True)
        async with srv:
            await srv.serve_forever()

    async def handle(self, creader, cwriter):
        cid = next(self._ids)
        try:
            breader, bwriter = await asyncio.open_connection(self.cfg.broker_host, self.cfg.broker_port)
        except OSError as e:
            print(f"[proxy] broker unreachable: {e}", flush=True)
            cwriter.close(); return
        st = {"conn_id": cid, "client_id": None, "keep_alive": 0, "swallowed": set(),
              "passthrough": False}
        t1 = asyncio.create_task(self._c2b(creader, cwriter, bwriter, st))
        t2 = asyncio.create_task(self._b2c(breader, cwriter, st))
        try:
            await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                t.cancel()
            for w in (cwriter, bwriter):
                try: w.close()
                except Exception: pass
            self.engine.on_disconnect(cid)

    # ---------------- client -> broker
    async def _c2b(self, cr, cw, bw, st):
        fr = codec.StreamFramer(self.cfg.max_packet_bytes)
        cfg = self.cfg
        try:
            while True:
                data = await cr.read(65536)
                if not data:
                    return
                self.counters["bytes_from_clients"] += len(data)
                if st["passthrough"]:
                    self._wb(bw, data); await bw.drain(); continue
                for raw in fr.feed(data):
                    self.counters["c2b_packets"] += 1
                    p = codec.parse(raw)
                    t = p["type"]
                    if t == codec.CONNECT:
                        if p["level"] not in (3, 4):
                            if cfg.mqtt5 == "passthrough":
                                st["passthrough"] = True
                                print(f"[IDS] WARNING MQTT level {p['level']} passed through UNINSPECTED",
                                      flush=True)
                                self._wb(bw, raw); continue
                            self._wc(cw, codec.build_connack(False, 1), True); await cw.drain(); return
                        st["client_id"] = p["client_id"] or f"anon-{st['conn_id']}"
                        st["keep_alive"] = p["keep_alive"]
                        self.engine.on_connect(st["conn_id"], st["client_id"], p["clean_session"],
                                               p["keep_alive"], time.time())
                        if self.feed:
                            self.feed.session(st["client_id"], p["keep_alive"], p["clean_session"])
                        self._wb(bw, raw)
                    elif t == codec.PUBLISH:
                        await self._publish(p, raw, cw, bw, st)
                    elif t == codec.PUBREL:
                        if p["packet_id"] in st["swallowed"]:     # IDS-owned QoS2 flow
                            st["swallowed"].discard(p["packet_id"])
                            self._wc(cw, codec.build_ack(codec.PUBCOMP, p["packet_id"]), True)
                        else:
                            self.engine.on_client_pubrel(st["conn_id"], p["packet_id"], time.time())
                            self._wb(bw, raw)
                    else:
                        self._wb(bw, raw)
                await bw.drain()
                await cw.drain()
        except (ConnectionError, OSError, codec.ProtocolError, asyncio.CancelledError):
            return

    async def _publish(self, p, raw, cw, bw, st):
        cfg = self.cfg
        self.counters["bytes_publish_in"] += len(raw)
        _t0 = time.perf_counter()
        d = self.engine.on_client_publish(st["conn_id"], p["topic"], p["payload"], p["qos"],
                                          p["dup"], p["packet_id"], time.time())
        _t1 = time.perf_counter()
        self.t_decide.append(_t1 - _t0)
        if d.action == DROP:
            self.counters["dropped"] += 1
            if cfg.drop_response == "ack":
                if p["qos"] == 1:
                    self._wc(cw, codec.build_ack(codec.PUBACK, p["packet_id"]), True)
                elif p["qos"] == 2:
                    st["swallowed"].add(p["packet_id"])
                    self._wc(cw, codec.build_ack(codec.PUBREC, p["packet_id"]), True)
            elif cfg.drop_response == "disconnect":
                raise ConnectionError("dropped replay -> disconnect")
            self.t_handle.append(time.perf_counter() - _t0)
            return
        out = raw
        if cfg.minimize and d.has_data:
            out = codec.rewrite_publish_payload(raw, minimized_payload(st["client_id"], d.data))
            self.feed.message(st["client_id"], p["topic"], d.data, st["keep_alive"])
        self.counters["forwarded_publish"] += 1
        self.counters["bytes_publish_out"] += len(out)
        self._wb(bw, out)
        self.t_handle.append(time.perf_counter() - _t0)

    # ---------------- broker -> client
    async def _b2c(self, br, cw, st):
        fr = codec.StreamFramer(self.cfg.max_packet_bytes * 4)
        try:
            while True:
                data = await br.read(65536)
                if not data:
                    return
                self.counters["bytes_from_broker"] += len(data)
                if st["passthrough"]:
                    self._wc(cw, data); await cw.drain(); continue
                for raw in fr.feed(data):
                    self.counters["b2c_packets"] += 1
                    t = raw[0] >> 4
                    if t in (codec.PUBACK, codec.PUBREC, codec.PUBCOMP):
                        p = codec.parse(raw)
                        self.engine.on_broker_ack(st["conn_id"], p["name"], p["packet_id"], time.time())
                    self._wc(cw, raw)
                await cw.drain()
        except (ConnectionError, OSError, codec.ProtocolError, asyncio.CancelledError):
            return


def main(argv=None):
    ap = argparse.ArgumentParser(description="Layered MQTT Replay IDS proxy")
    ap.add_argument("--config", required=True)
    ap.add_argument("--listen-port", type=int); ap.add_argument("--broker-port", type=int)
    ap.add_argument("--decision-log"); ap.add_argument("--app-feed"); ap.add_argument("--stats")
    a = ap.parse_args(argv)
    cfg = Config.load(a.config)
    for k, v in (("listen_port", a.listen_port), ("broker_port", a.broker_port),
                 ("decision_log", a.decision_log), ("app_feed", a.app_feed), ("stats_path", a.stats)):
        if v is not None:
            setattr(cfg, k, v)
    proxy = ReplayProxy(cfg)
    try:
        asyncio.run(proxy.serve())
    except KeyboardInterrupt:
        proxy.dump_stats()
        print("\n[proxy] stopped; counters:", proxy.counters, flush=True)
        print("[proxy] decisions:", dict(proxy.engine.stats), flush=True)


if __name__ == "__main__":
    main()
