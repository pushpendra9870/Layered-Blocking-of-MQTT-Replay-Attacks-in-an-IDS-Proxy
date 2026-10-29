"""Socket-level tests: real TCP through proxy to the mini broker. SYNTHETIC data."""
import asyncio, json, sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tests.harness import Rig, signed, MQTTClient
from replay_ids import codec
from replay_ids.minimizer import VERIFICATION_ONLY_KEYS

T = "plant/temp"
def run(coro): return asyncio.run(coro)


async def send_ack1(c, seq, pid, dup=False, topic=T):
    await c.publish(topic, signed(topic, {"v": seq}, seq), 1, pid=pid, dup=dup)


class TestOutput1NoIDS(unittest.TestCase):
    def test_replay_reaches_broker_and_subscribers(self):
        async def go():
            async with Rig(use_proxy=False) as r:
                c = await r.client("dev1")
                await send_ack1(c, 1, 1); await c.wait_for(lambda: len(c.completed) == 1)
                await send_ack1(c, 1, 1); await send_ack1(c, 1, 1, dup=True)
                await c.wait_for(lambda: len(c.completed) == 3); await r.settle()
                self.assertEqual(r.broker_received(), 3)
                self.assertEqual(len(r.delivered()), 3)
        run(go())


class TestOutput2Layered(unittest.TestCase):
    def test_replay_dropped_before_broker_and_client_still_acked(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                await send_ack1(c, 1, 1); await c.wait_for(lambda: len(c.completed) == 1)
                await send_ack1(c, 1, 1)                       # exact
                await send_ack1(c, 1, 1, dup=True)             # dup-evasion
                await c.wait_for(lambda: len(c.completed) == 3); await r.settle()
                self.assertEqual(r.broker_received(), 1, "replays must not reach the broker")
                self.assertEqual(len(r.delivered()), 1)
                self.assertEqual(c.completed, [1, 1, 1], "client state machine kept consistent")
                acts = [(d["classification"], d["action"]) for d in r.decisions()]
                self.assertEqual(acts, [("legit", "forward"), ("replay", "drop"), ("replay", "drop")])
                for d in r.decisions():
                    self.assertTrue(d["detector"] and d["reason"] and d["action"])
        run(go())

    def test_legit_retransmission_reaches_broker(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                await send_ack1(c, 1, 5)
                await send_ack1(c, 1, 5, dup=True)             # in-flight DUP resend
                await c.wait_for(lambda: len(c.completed) >= 2); await r.settle()
                self.assertEqual(r.broker_received(), 2)         # at-least-once preserved
                self.assertTrue(all(d["action"] == "forward" for d in r.decisions()))
        run(go())

    def test_pid_reuse_after_completion_delivered(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                for seq in (1, 2, 3):                          # same packet id each time
                    await send_ack1(c, seq, 9)
                    await c.wait_for(lambda s=seq: len(c.completed) == s)
                await r.settle()
                self.assertEqual(r.broker_received(), 3)
        run(go())

    def test_invalid_hmac_and_unsigned_never_reach_broker(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                bad = signed(T, {"v": 1}, 1).replace(b'"v": 1', b'"v": 2')
                await c.publish(T, bad, 1, pid=1)
                await c.publish(T, b"unsigned", 1, pid=2)
                await c.wait_for(lambda: len(c.completed) == 2); await r.settle()
                self.assertEqual(r.broker_received(), 0)
                self.assertEqual([d["reason"] for d in r.decisions()], ["invalid_hmac", "missing_signature"])
        run(go())

    def test_qos2_end_to_end_and_replay_dropped(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                await c.publish(T, signed(T, {"v": 1}, 1), 2, pid=4)
                await c.wait_for(lambda: 4 in c.completed)
                self.assertEqual(r.broker_received(), 1)
                n = len(c.completed)
                await c.publish(T, signed(T, {"v": 1}, 1), 2, pid=4, dup=True)   # replay
                await c.wait_for(lambda: len(c.completed) == n + 1); await r.settle()
                self.assertEqual(r.broker_received(), 1)
                self.assertEqual(len(r.delivered()), 1)
                self.assertEqual(c.pubrecs, [4, 4])           # IDS synthesised PUBREC, then PUBCOMP
        run(go())

    def test_qos2_new_message_after_completion_delivered_once(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                for seq in (1, 2):
                    await c.publish(T, signed(T, {"v": seq}, seq), 2, pid=4)
                    await c.wait_for(lambda s=seq: len(c.completed) == s)
                await r.settle()
                self.assertEqual(r.broker_received(), 2)
        run(go())

    def test_persistent_session_reconnect_retransmit_and_replay(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1", clean=False)
                await send_ack1(c, 1, 1); await c.wait_for(lambda: 1 in c.completed)
                await c.close(send_disconnect=False)
                c2 = await r.client("dev1", clean=False)
                self.assertTrue(c2.session_present)
                await send_ack1(c2, 2, 2)
                await c2.wait_for(lambda: 2 in c2.completed)
                await send_ack1(c2, 1, 1, dup=True)           # replay of seq 1 after reconnect
                await c2.wait_for(lambda: len(c2.completed) == 2); await r.settle()
                self.assertEqual(r.broker_received(), 2)
                self.assertEqual(r.decisions()[-1]["classification"], "replay")
        run(go())

    def test_clean_session_reconnect_replay_blocked_by_seq_layer(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                await send_ack1(c, 1, 1); await c.wait_for(lambda: 1 in c.completed)
                await c.close()
                c2 = await r.client("dev1")                   # clean session: packet-id state gone
                await send_ack1(c2, 1, 1); await c2.wait_for(lambda: 1 in c2.completed); await r.settle()
                self.assertEqual(r.broker_received(), 1)
                self.assertEqual(r.decisions()[-1]["reason"], "replay_seq_already_accepted")
        run(go())

    def test_subscriber_through_proxy_is_bidirectional(self):
        async def go():
            async with Rig() as r:
                s = await r.client("sub-via-proxy", keep_alive=2)
                self.assertEqual(await s.subscribe("plant/#", 1, pid=3), [1])
                pub = await r.client("dev1")
                await send_ack1(pub, 1, 1)
                await s.wait_for(lambda: len(s.received) == 1)
                self.assertEqual(len(s.received), 1)
                s.send_raw(codec.PINGREQ_PKT)                  # keep-alive passes both ways
                await asyncio.sleep(0.2)
                self.assertFalse(s.closed.is_set())
        run(go())

    def test_fragmented_and_coalesced_tcp_writes(self):
        async def go():
            async with Rig() as r:
                c = await r.client("dev1")
                blob = b"".join(codec.build_publish(T, i, signed(T, {"v": i}, i), 1) for i in (1, 2, 3))
                for i in range(0, len(blob), 5):
                    c.writer.write(blob[i:i + 5]); await c.writer.drain(); await asyncio.sleep(0)
                await c.wait_for(lambda: len(c.completed) == 3); await r.settle()
                self.assertEqual(r.broker_received(), 3)
        run(go())

    def test_mqtt5_connect_rejected(self):
        async def go():
            async with Rig() as r:
                c = MQTTClient("127.0.0.1", r.target, "v5dev")
                c.writer = None
                rd, wr = await asyncio.open_connection("127.0.0.1", r.target)
                wr.write(codec.build_connect("v5dev", 30, True, level=5) + b"\x00")
                data = await asyncio.wait_for(rd.read(10), 2)
                self.assertEqual(data[:4], b"\x20\x02\x00\x01")
        run(go())

    def test_drop_response_silent_and_disconnect(self):
        async def go():
            async with Rig(drop_response="silent") as r:
                c = await r.client("dev1")
                await send_ack1(c, 1, 1); await c.wait_for(lambda: 1 in c.completed)
                await send_ack1(c, 1, 1); await asyncio.sleep(0.2)
                self.assertEqual(c.completed, [1])             # no ack for the dropped replay
            async with Rig(drop_response="disconnect") as r:
                c = await r.client("dev1")
                await send_ack1(c, 1, 1); await c.wait_for(lambda: 1 in c.completed)
                await send_ack1(c, 1, 1)
                self.assertTrue(await asyncio.wait_for(c.closed.wait(), 2))
        run(go())


class TestOutput3Minimized(unittest.TestCase):
    def test_application_facing_payload_is_minimal(self):
        async def go():
            async with Rig(minimize=True) as r:
                r.proxy.feed.fh = None
                c = await r.client("dev-77", keep_alive=42)
                await send_ack1(c, 1, 1); await c.wait_for(lambda: 1 in c.completed); await r.settle()
                (topic, payload), = r.delivered()
                obj = json.loads(payload)
                self.assertEqual(topic, T)
                self.assertEqual(set(obj), {"client_id", "message"})
                self.assertEqual(obj, {"client_id": "dev-77", "message": {"v": 1}})
                for k in VERIFICATION_ONLY_KEYS:
                    self.assertNotIn(k.encode(), payload)
                self.assertLess(len(payload), len(signed(T, {"v": 1}, 1)))
        run(go())

    def test_replay_still_dropped_and_feed_has_keepalive(self):
        async def go():
            import tempfile, os
            fd, path = tempfile.mkstemp(suffix=".jsonl"); os.close(fd)
            try:
                async with Rig(minimize=True, app_feed=path) as r:
                    from replay_ids.minimizer import AppFeed
                    r.proxy.feed = AppFeed(path)
                    c = await r.client("dev-77", keep_alive=42)
                    await send_ack1(c, 1, 1); await c.wait_for(lambda: 1 in c.completed)
                    await send_ack1(c, 1, 1); await send_ack1(c, 1, 1, dup=True)
                    await c.wait_for(lambda: len(c.completed) == 3); await r.settle()
                    self.assertEqual(r.broker_received(), 1)
                recs = [json.loads(l) for l in open(path)]
                self.assertEqual([x["type"] for x in recs], ["session", "message"])
                self.assertEqual(recs[0]["keep_alive"], 42)
                self.assertEqual(set(recs[1]), {"type", "client_id", "topic", "message", "keep_alive"})
            finally:
                os.unlink(path)
        run(go())

    def test_equivalence_output2_vs_output3_on_scripted_scenario(self):
        async def scenario(minimize):
            async with Rig(minimize=minimize) as r:
                if minimize:
                    from replay_ids.minimizer import AppFeed
                    r.proxy.feed = AppFeed("")
                c = await r.client("devA", clean=False)
                await send_ack1(c, 1, 1); await c.wait_for(lambda: 1 in c.completed)
                await send_ack1(c, 1, 1); await send_ack1(c, 1, 1, dup=True)      # replays
                await send_ack1(c, 2, 2); await send_ack1(c, 2, 2, dup=True)      # retransmit
                await c.publish(T, b"junk", 1, pid=3)                            # unsigned
                await c.publish(T, signed(T, {"v": 3}, 3).replace(b'"v": 3', b'"v": 9'), 1, pid=4)
                await send_ack1(c, 4, 1)                                          # pid reuse, fresh
                await c.wait_for(lambda: len(c.completed) >= 7); await r.settle(0.4)
                sig = [(d["classification"], d["reason"], d["action"], d["detector"]) for d in r.decisions()]
                return sig, r.broker_received()
        a, ra = run(scenario(False)); b, rb = run(scenario(True))
        self.assertEqual(a, b)
        self.assertEqual(ra, rb)
        self.assertGreater(len(a), 6)


if __name__ == "__main__":
    unittest.main(verbosity=2)
