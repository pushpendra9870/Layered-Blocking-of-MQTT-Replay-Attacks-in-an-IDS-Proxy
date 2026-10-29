"""Engine-level tests (no sockets). All data here is SYNTHETIC."""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from replay_ids import _legacy  # noqa
from replay_ids.config import Config
from replay_ids.engine import LayeredReplayEngine
from detectors import PacketIdReuseRule, HmacFreshnessRule, MQTTPacketInfo
import signing

T = "dev/temp"
def P(seq, data=None, topic=T, ts="1.0", key=None):
    return signing.build_signed_payload(topic, data if data is not None else {"v": seq}, seq, ts,
                                        **({"key": key} if key else {}))


class Base(unittest.TestCase):
    def setUp(self, **cfg):
        self.cfg = Config(console=False, **cfg)
        self.e = LayeredReplayEngine(self.cfg)
        self.now = 100.0
        self.e.on_connect("c1", "dev1", True, 60, now=self.now)

    def pub(self, payload, pid=1, qos=1, dup=False, conn="c1", dt=0.1, topic=T):
        self.now += dt
        return self.e.on_client_publish(conn, topic, payload, qos, dup, pid, self.now)

    def ack(self, pid, name="PUBACK", conn="c1", dt=0.1):
        self.now += dt
        self.e.on_broker_ack(conn, name, pid, self.now)

    def assertV(self, d, action, cls, reason=None):
        self.assertEqual((d.action, d.classification), (action, cls), d.detail)
        if reason:
            self.assertEqual(d.reason, reason)


class TestLegit(Base):
    def test_qos1_fresh_sequence(self):
        for i in range(1, 6):
            self.assertV(self.pub(P(i), pid=i), "forward", "legit", "fresh_sequence")
            self.ack(i)

    def test_qos1_retransmit_while_in_flight_is_legit(self):
        self.pub(P(1))
        self.assertV(self.pub(P(1), dup=True), "forward", "legit", "retransmit_inflight")
        self.assertV(self.pub(P(1), dup=True), "forward", "legit", "retransmit_inflight")

    def test_qos2_full_handshake_and_retransmits(self):
        self.assertV(self.pub(P(1), qos=2), "forward", "legit")
        self.assertV(self.pub(P(1), qos=2, dup=True), "forward", "legit", "retransmit_inflight")  # PUBREC lost
        self.ack(1, "PUBREC")
        self.assertV(self.pub(P(1), qos=2, dup=True), "forward", "legit", "retransmit_inflight")
        self.e.on_client_pubrel("c1", 1, self.now)
        self.assertV(self.pub(P(1), qos=2, dup=True), "forward", "legit", "retransmit_inflight")
        self.ack(1, "PUBCOMP")
        # completed -> any further copy is a replay
        self.assertV(self.pub(P(1), qos=2, dup=True), "drop", "replay", "replay_completed_transaction")

    def test_qos2_not_completed_by_pubrec_alone(self):
        self.pub(P(1), qos=2); self.ack(1, "PUBREC")
        self.assertV(self.pub(P(1), qos=2), "drop", "replay", "replay_duplicate_inflight_nodup")

    def test_pid_reuse_after_completion_with_fresh_seq_is_legit(self):
        self.pub(P(1), pid=7); self.ack(7)
        d = self.pub(P(2), pid=7)
        self.assertV(d, "forward", "legit", "pid_reuse_after_completion_fresh_seq")
        # the ORIGINAL rule would have called this an attack (documented false positive)
        self.assertTrue(d.signals["packet_id"]["legacy_flag"])
        legacy = PacketIdReuseRule()
        mk = lambda t, pid: MQTTPacketInfo("1.1.1.1", "2.2.2.2", 5000, 1883, t, qos=1, packet_id=pid)
        legacy.analyze(mk("PUBLISH", 7)); legacy.analyze(mk("PUBACK", 7))
        self.assertIsNotNone(legacy.analyze(mk("PUBLISH", 7)))

    def test_dup_retransmit_of_unobserved_original_late_seq(self):
        for i in range(1, 51):
            if i == 40:
                continue                       # original of seq 40 was never seen by the IDS
            self.pub(P(i), pid=i); self.ack(i)
        self.assertV(self.pub(P(40, topic="other"), pid=900, dup=True, topic="other"),
                     "forward", "legit", "retransmit_original_unobserved")
        # the same late DUP can be accepted only ONCE
        self.assertV(self.pub(P(40, topic="other"), pid=900, dup=True, topic="other"),
                     "forward", "legit", "retransmit_inflight")


class TestReplay(Base):
    def test_exact_replay_dup0(self):
        self.pub(P(1)); self.ack(1)
        self.assertV(self.pub(P(1)), "drop", "replay", "replay_completed_transaction")

    def test_dup_evasion_replay(self):
        self.pub(P(1)); self.ack(1)
        d = self.pub(P(1), dup=True)
        self.assertV(d, "drop", "replay", "replay_completed_transaction")
        # original Packet-ID rule alone is blind to this
        self.assertFalse(d.signals["packet_id"]["legacy_flag"])

    def test_stale_sequence_replay_below_window(self):
        for i in range(1, 400):
            if i == 3:
                continue
            self.pub(P(i), pid=(i % 60000) + 1); self.ack((i % 60000) + 1)
        d = self.pub(P(3, topic="x"), pid=5000, dup=True, topic="x")   # DUP bit does not help attacker
        self.assertV(d, "drop", "replay", "replay_stale_sequence")

    def test_late_sequence_nodup_is_replay(self):
        for i in range(1, 11):
            if i == 5:
                continue
            self.pub(P(i), pid=i); self.ack(i)
        self.assertV(self.pub(P(5, topic="o"), pid=99, topic="o"), "drop", "replay", "replay_late_sequence_nodup")

    def test_replay_on_new_pid(self):
        self.pub(P(1), pid=1); self.ack(1)
        d = self.pub(P(1), pid=2)
        self.assertEqual(d.classification, "replay")     # attacker picks a fresh packet id

    def test_same_seq_different_content_rejected_by_hmac_first(self):
        self.pub(P(1)); self.ack(1)
        forged = P(1, data={"v": 999})
        d = self.pub(forged, pid=3)
        self.assertEqual(d.classification, "replay")      # valid key holder reusing seq => mismatch
        self.assertEqual(d.reason, "replay_seq_content_mismatch")

    def test_inflight_nodup_duplicate_is_replay(self):
        self.pub(P(1))
        self.assertV(self.pub(P(1)), "drop", "replay", "replay_duplicate_inflight_nodup")

    def test_qos0_replay(self):
        self.pub(P(1), qos=0, pid=0)
        self.assertV(self.pub(P(1), qos=0, pid=0), "drop", "replay", "replay_seq_already_accepted")

    def test_dropped_packet_does_not_poison_state(self):
        self.pub(P(1)); self.ack(1)
        self.pub(P(1)); self.pub(P(1))               # two dropped replays
        self.assertV(self.pub(P(2), pid=2), "forward", "legit", "fresh_sequence")

    def test_stale_timestamp_when_enabled(self):
        self.setUp(ts_max_age_s=30.0)
        d = self.pub(P(1, ts="10.0"))
        self.assertV(d, "drop", "replay", "replay_stale_timestamp")
        self.assertV(self.pub(P(2, ts=f"{self.now:.3f}")), "forward", "legit")


class TestKnownLimitations(Base):
    def test_cross_identity_replay_is_NOT_detected(self):
        """DOCUMENTED LIMITATION: the HMAC covers topic|data|seq|ts, not the sender identity, and replay
        state is per client-id. A captured message re-sent under ANOTHER client-id looks fresh."""
        self.pub(P(1)); self.ack(1)
        self.e.on_connect("c9", "other-client", True, 60, now=self.now)
        d = self.pub(P(1), conn="c9")
        self.assertV(d, "forward", "legit", "fresh_sequence")     # mitigation needs identity-bound MAC (future work)


class TestInvalid(Base):
    def test_invalid_hmac_tampered_data(self):
        bad = P(1).replace(b'"v": 1', b'"v": 2')
        self.assertV(self.pub(bad), "drop", "invalid", "invalid_hmac")

    def test_invalid_hmac_wrong_key(self):
        self.assertV(self.pub(P(1, key=b"attacker-key")), "drop", "invalid", "invalid_hmac")

    def test_invalid_hmac_does_not_consume_sequence(self):
        self.pub(P(1, key=b"attacker-key"))
        self.assertV(self.pub(P(1)), "forward", "legit", "fresh_sequence")

    def test_missing_signature_variants(self):
        for payload in (b"plain text", b'{"data":1}', b'{"data":1,"seq":"x","ts":"1","sig":"a"}', b"\xff\xfe"):
            self.assertV(self.pub(payload), "drop", "invalid", "missing_signature")

    def test_policy_forward_for_missing_signature(self):
        self.setUp(on_missing_signature="forward")
        self.assertV(self.pub(b"plain"), "forward", "invalid", "missing_signature")

    def test_hmac_alone_is_not_replay_prevention(self):
        """A perfectly valid HMAC on a replayed message must still be dropped."""
        self.pub(P(1)); self.ack(1)
        d = self.pub(P(1))
        self.assertEqual(d.signals["hmac_freshness"]["status"], "seen")
        self.assertEqual(d.action, "drop")


class TestSessions(Base):
    def reconnect(self, clean, dt=0.5):
        self.e.on_disconnect("c1")
        self.now += dt
        self.e.on_connect("c2", "dev1", clean, 60, now=self.now)

    def test_resume_session_resends_unacked_with_dup(self):
        self.pub(P(1), pid=1); self.pub(P(2), pid=2); self.ack(1)   # pid 2 unacked
        self.reconnect(clean=False)
        self.assertV(self.pub(P(2), pid=2, dup=True, conn="c2"), "forward", "legit", "retransmit_inflight")

    def test_clean_session_clears_pid_state_but_not_seq_state(self):
        self.pub(P(1), pid=1); self.ack(1)
        self.reconnect(clean=True)
        # packet-id layer is blind after a clean session; HMAC/seq layer still blocks
        d = self.pub(P(1), pid=1, conn="c2")
        self.assertEqual(d.signals["packet_id"]["state"], "unused")
        self.assertV(d, "drop", "replay", "replay_seq_already_accepted")
        self.assertV(self.pub(P(2), pid=1, conn="c2"), "forward", "legit")

    def test_replay_after_reconnect_persistent_session_blocked(self):
        self.pub(P(1), pid=1); self.ack(1)
        self.reconnect(clean=False)
        self.pub(P(5), pid=5, conn="c2")                      # new traffic first
        self.assertV(self.pub(P(1), pid=1, dup=True, conn="c2"), "drop", "replay",
                     "replay_completed_transaction")

    def test_lost_ack_retransmit_is_uncertain_and_forwarded_by_default(self):
        self.pub(P(1), pid=1); self.ack(1)                    # ack relayed, then link died
        self.reconnect(clean=False)
        d = self.pub(P(1), pid=1, dup=True, conn="c2")
        self.assertV(d, "forward", "uncertain", "possible_lost_ack_retransmit")

    def test_lost_ack_uncertain_policy_drop(self):
        self.setUp(uncertain_action="drop")
        self.pub(P(1), pid=1); self.ack(1)
        self.reconnect(clean=False)
        self.assertV(self.pub(P(1), pid=1, dup=True, conn="c2"), "drop", "uncertain")

    def test_lost_ack_outside_resend_window_is_replay(self):
        self.pub(P(1), pid=1); self.ack(1)
        self.reconnect(clean=False)
        self.now += self.cfg.resend_window_s + 1
        self.assertV(self.pub(P(1), pid=1, dup=True, conn="c2"), "drop", "replay")

    def test_old_connection_state_isolated_per_client(self):
        self.pub(P(1)); self.ack(1)
        self.e.on_connect("cX", "other-dev", True, 60, now=self.now)
        self.assertV(self.pub(P(1), conn="cX"), "forward", "legit")   # separate seq space

    def test_pid_in_flight_reuse_is_uncertain(self):
        self.pub(P(1), pid=3)
        self.assertV(self.pub(P(2), pid=3), "forward", "uncertain", "pid_in_flight_reuse")


if __name__ == "__main__":
    unittest.main(verbosity=2)
