"""Minimal MQTT 3.1.1 broker (QoS 0/1/2, persistent sessions, wildcards) so the
project runs on Windows with Python only. NOT a production broker: no auth, TLS,
retained messages or will messages. Logs every PUBLISH it receives (JSONL), which
is the ground truth for 'what actually reached the broker'."""
import argparse, asyncio, json, time
from . import codec


def topic_match(filt, topic):
    f, t = filt.split("/"), topic.split("/")
    for i, part in enumerate(f):
        if part == "#":
            return True
        if i >= len(t):
            return False
        if part != "+" and part != t[i]:
            return False
    return len(f) == len(t)


class Session:
    def __init__(self, cid, clean):
        self.cid, self.clean = cid, clean
        self.subs, self.conn = {}, None
        self.out = {}            # pid -> [topic, payload, qos, state]
        self.queue = []
        self.in_qos2 = set()
        self.next_pid = 0

    def alloc(self):
        for _ in range(65535):
            self.next_pid = self.next_pid % 65535 + 1
            if self.next_pid not in self.out:
                return self.next_pid
        raise RuntimeError("no free packet id")


class Broker:
    def __init__(self, host="127.0.0.1", port=1883, log_path=None):
        self.host, self.port = host, port
        self.sessions = {}
        self.log = open(log_path, "w", encoding="utf-8") if log_path else None
        self.received = 0
        self.routed = 0

    async def serve(self):
        srv = await asyncio.start_server(self.handle, self.host, self.port)
        print(f"[mini_broker] listening on {self.host}:{self.port}", flush=True)
        async with srv:
            await srv.serve_forever()

    def _log(self, **kw):
        if self.log:
            self.log.write(json.dumps(kw) + "\n"); self.log.flush()

    async def handle(self, reader, writer):
        fr, sess = codec.StreamFramer(), None
        clean_exit = False
        try:
            ka = 10
            while True:
                data = await asyncio.wait_for(reader.read(65536), timeout=ka)
                if not data:
                    break
                for raw in fr.feed(data):
                    p = codec.parse(raw)
                    t = p["type"]
                    if sess is None:
                        if t != codec.CONNECT:
                            return
                        sess = await self._connect(p, writer)
                        if sess is None:
                            return
                        ka = p["keep_alive"] * 1.5 if p["keep_alive"] else 3600
                        continue
                    if t == codec.PUBLISH:
                        self._publish(sess, p, writer)
                    elif t == codec.PUBACK:
                        sess.out.pop(p["packet_id"], None)
                    elif t == codec.PUBREC:
                        e = sess.out.get(p["packet_id"])
                        if e: e[3] = "rel"
                        writer.write(codec.build_ack(codec.PUBREL, p["packet_id"]))
                    elif t == codec.PUBREL:
                        sess.in_qos2.discard(p["packet_id"])
                        writer.write(codec.build_ack(codec.PUBCOMP, p["packet_id"]))
                    elif t == codec.PUBCOMP:
                        sess.out.pop(p["packet_id"], None)
                    elif t == codec.SUBSCRIBE:
                        pid, flt = codec.parse_subscribe(raw)
                        for f, q in flt:
                            sess.subs[f] = min(q, 2)
                        writer.write(codec.build_suback(pid, [min(q, 2) for _, q in flt]))
                    elif t == codec.UNSUBSCRIBE:
                        pid, flt = codec.parse_unsubscribe(raw)
                        for f in flt:
                            sess.subs.pop(f, None)
                        writer.write(codec.build_ack(codec.UNSUBACK, pid))
                    elif t == codec.PINGREQ:
                        writer.write(codec.PINGRESP_PKT)
                    elif t == codec.DISCONNECT:
                        clean_exit = True
                        return
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError, codec.ProtocolError):
            pass
        finally:
            if sess and sess.conn is writer:
                sess.conn = None
                if sess.clean:
                    self.sessions.pop(sess.cid, None)
            try:
                writer.close()
            except Exception:
                pass

    async def _connect(self, p, writer):
        if p["level"] not in (3, 4):
            writer.write(codec.build_connack(False, 1)); await writer.drain(); return None
        cid = p["client_id"] or f"auto-{time.time_ns()}"
        old = self.sessions.get(cid)
        present = False
        if old and old.conn is not None:
            try: old.conn.close()
            except Exception: pass
            old.conn = None
        if old and not p["clean_session"] and not old.clean:
            sess, present = old, True
        else:
            sess = Session(cid, p["clean_session"])
        self.sessions[cid] = sess
        sess.clean = p["clean_session"]
        sess.conn = writer
        writer.write(codec.build_connack(present, 0))
        if present:                                   # resume: resend in-flight, flush queue
            for pid, (tp, pl, q, st) in list(sess.out.items()):
                if st == "rel":
                    writer.write(codec.build_ack(codec.PUBREL, pid))
                else:
                    writer.write(codec.build_publish(tp, pid, pl, q, dup=True))
            for tp, pl, q in sess.queue:
                self._deliver(sess, tp, pl, q)
            sess.queue.clear()
        await writer.drain()
        return sess

    def _publish(self, sess, p, writer):
        qos, pid = p["qos"], p["packet_id"]
        new = True
        if qos == 2:
            new = pid not in sess.in_qos2
            sess.in_qos2.add(pid)
        self.received += 1
        self._log(t=time.time(), client_id=sess.cid, topic=p["topic"], qos=qos,
                  pid=pid, dup=p["dup"], size=len(p["payload"]), routed=new)
        if new:
            self._route(p["topic"], p["payload"], qos)
        if qos == 1:
            writer.write(codec.build_ack(codec.PUBACK, pid))
        elif qos == 2:
            writer.write(codec.build_ack(codec.PUBREC, pid))

    def _route(self, topic, payload, qos):
        for s in list(self.sessions.values()):
            sub_q = [q for f, q in s.subs.items() if topic_match(f, topic)]
            if not sub_q:
                continue
            q = min(qos, max(sub_q))
            self.routed += 1
            if s.conn is not None:
                self._deliver(s, topic, payload, q)
            elif not s.clean and q > 0 and len(s.queue) < 10000:
                s.queue.append((topic, payload, q))

    def _deliver(self, s, topic, payload, q):
        pid = s.alloc() if q else 0
        if q:
            s.out[pid] = [topic, payload, q, "pub"]
        s.conn.write(codec.build_publish(topic, pid, payload, q))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--log", default=None, help="JSONL log of every PUBLISH received")
    a = ap.parse_args()
    try:
        asyncio.run(Broker(a.host, a.port, a.log).serve())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
