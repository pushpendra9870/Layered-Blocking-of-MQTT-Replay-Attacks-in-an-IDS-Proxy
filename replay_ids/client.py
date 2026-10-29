"""Small asyncio MQTT 3.1.1 client used by the evaluation driver, tests and consumer.
Deliberately low-level: caller controls packet id and DUP so retransmissions and
replays can be generated exactly."""
import asyncio, time
from . import codec


class MQTTClient:
    def __init__(self, host, port, client_id, clean=True, keep_alive=60, auto_pubrel=True):
        self.host, self.port, self.client_id = host, port, client_id
        self.clean, self.keep_alive, self.auto_pubrel = clean, keep_alive, auto_pubrel
        self.reader = self.writer = None
        self.completed = []          # pids completed (PUBACK for QoS1, PUBCOMP for QoS2)
        self.pubrecs = []
        self.received = []           # (topic, payload, qos, pid, dup)
        self.session_present = None
        self.closed = asyncio.Event()
        self._task = None
        self._connack = asyncio.get_event_loop().create_future()
        self.suback = {}
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.ack_log = []            # (pid, perf_counter) for PUBACK/PUBCOMP
        self.recv_log = []           # (topic, payload, perf_counter)

    async def connect(self, timeout=5):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        self._task = asyncio.create_task(self._read_loop())
        _p = codec.build_connect(self.client_id, self.keep_alive, self.clean); self.tx_bytes += len(_p)
        self.writer.write(_p)
        await self.writer.drain()
        rc = await asyncio.wait_for(self._connack, timeout)
        if rc != 0:
            raise ConnectionError(f"CONNACK rc={rc}")
        return self

    async def _read_loop(self):
        fr = codec.StreamFramer()
        try:
            while True:
                data = await self.reader.read(65536)
                if not data:
                    break
                self.rx_bytes += len(data)
                for raw in fr.feed(data):
                    self._on(codec.parse(raw))
        except (ConnectionError, OSError, codec.ProtocolError):
            pass
        finally:
            self.closed.set()
            if not self._connack.done():
                self._connack.set_exception(ConnectionError("closed before CONNACK"))

    def _on(self, p):
        t = p["type"]
        if t == codec.CONNACK:
            self.session_present = bool(p["raw"][2] & 1)
            if not self._connack.done():
                self._connack.set_result(p["raw"][3])
        elif t == codec.PUBACK:
            self.completed.append(p["packet_id"]); self.ack_log.append((p["packet_id"], time.perf_counter()))
        elif t == codec.PUBREC:
            self.pubrecs.append(p["packet_id"])
            if self.auto_pubrel:
                self.writer.write(codec.build_ack(codec.PUBREL, p["packet_id"]))
        elif t == codec.PUBCOMP:
            self.completed.append(p["packet_id"]); self.ack_log.append((p["packet_id"], time.perf_counter()))
        elif t == codec.SUBACK:
            self.suback[p["raw"][2] << 8 | p["raw"][3]] = list(p["raw"][4:])
        elif t == codec.PUBLISH:
            self.received.append((p["topic"], p["payload"], p["qos"], p["packet_id"], p["dup"]))
            self.recv_log.append((p["topic"], p["payload"], time.perf_counter()))
            if p["qos"] == 1:
                self.writer.write(codec.build_ack(codec.PUBACK, p["packet_id"]))
            elif p["qos"] == 2:
                self.writer.write(codec.build_ack(codec.PUBREC, p["packet_id"]))
        elif t == codec.PUBREL:
            self.writer.write(codec.build_ack(codec.PUBCOMP, p["packet_id"]))

    def publish_nowait(self, topic, payload, qos=1, pid=0, dup=False, retain=False):
        _p = codec.build_publish(topic, pid, payload, qos, dup, retain); self.tx_bytes += len(_p)
        self.writer.write(_p)

    async def publish(self, topic, payload, qos=1, pid=0, dup=False, retain=False):
        self.publish_nowait(topic, payload, qos, pid, dup, retain)
        await self.writer.drain()

    def send_raw(self, raw):
        self.writer.write(raw)

    async def subscribe(self, filt, qos=1, pid=1, timeout=5):
        self.writer.write(codec.build_subscribe(pid, [(filt, qos)]))
        await self.writer.drain()
        await self.wait_for(lambda: pid in self.suback, timeout)
        return self.suback[pid]

    async def wait_for(self, cond, timeout=5.0):
        end = asyncio.get_event_loop().time() + timeout
        while not cond():
            if asyncio.get_event_loop().time() > end:
                return False
            if self.closed.is_set() and not cond():
                return False
            await asyncio.sleep(0.005)
        return True

    async def close(self, send_disconnect=True):
        try:
            if send_disconnect and not self.closed.is_set():
                self.writer.write(codec.DISCONNECT_PKT)
                await self.writer.drain()
        except Exception:
            pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass
        if self._task:
            self._task.cancel()
