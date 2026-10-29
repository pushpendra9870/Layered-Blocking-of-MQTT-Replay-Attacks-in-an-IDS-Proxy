"""Tests for the integrated external-CSV pipeline (prepare_external_replay_csv.py). SYNTHETIC tiny CSV."""
import asyncio, csv, json, subprocess, sys, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "eval"))
from tests.harness import Rig
from replay_ids import codec
from live_eval import load as live_load
from offline_eval import LayeredAdapter, legacy_score
from replay_ids.config import Config

COLS = ["uuid", "timestamp", "topic", "payload", "modificado", "fuente", "tipo_ataque", "nuevo_topic"]
ROWS = [  # uuid, ts, topic, payload, label
    ("u1", "2025-01-01T00:00:01", "plant/a", '{"v": 1}', ""), ("u2", "2025-01-01T00:00:02", "plant/a", '{"v": 2}', ""),
    ("u3", "2025-01-01T00:00:03", "plant/a", '{"v": 1}', ""),                       # same payload again (legit, new seq)
    ("u4", "2025-01-01T00:00:04", "plant/a", '{"v": 1}', "replay attack"),          # matches u3 (latest original)
    ("u5", "2025-01-01T00:00:05", "plant/a", '{"v": 99}', "replay attack"),         # no original -> excluded
    ("u6", "2025-01-01T00:00:06", "plant/a", '{"v": 7}', "dos"),                    # unknown label -> excluded by guard
]


def build_fixture():
    tmp = tempfile.TemporaryDirectory(); T = Path(tmp.name)
    with (T / "in.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(COLS)
        for u, ts, tp, pl, lab in ROWS: w.writerow([u, ts, tp, pl, "1" if lab else "0", "0", lab, ""])
    r = subprocess.run([sys.executable, str(ROOT / "prepare_external_replay_csv.py"), "--csv", str(T / "in.csv"),
                        "--out", str(T / "out.json"), "--manifest", str(T / "man.json")], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    return tmp, T, json.loads((T / "out.json").read_text()), json.loads((T / "man.json").read_text())


class TestPrepare(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.T, cls.recs, cls.man = build_fixture()

    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def test_counts_and_exclusions(self):
        self.assertEqual(sum(r["truth"] == "legit" for r in self.recs), 3)
        self.assertEqual(sum(r["truth"] == "replay" for r in self.recs), 1)
        self.assertEqual(self.man["attack_labeled_rows_excluded_as_unmatched"], 1)
        self.assertEqual(self.man["rows_excluded_unrecognised_label"], 1)        # integration guard

    def test_replay_copies_latest_matching_original(self):
        legit = [r for r in self.recs if r["truth"] == "legit"]; rep = next(r for r in self.recs if r["truth"] == "replay")
        src = legit[2]                                                             # u3, not u1
        self.assertEqual(rep["source_csv_line"], src["csv_line"])
        for k in ("packet_id", "payload_hex", "topic"): self.assertEqual(rep["packet"][k], src["packet"][k])
        self.assertFalse(rep["packet"]["dup"])

    def test_schema_loads_in_live_evaluator(self):
        recs, per = live_load(str(self.T / "out.json"))
        self.assertEqual(len(recs), 4); self.assertEqual(len(per), 1)

    def test_offline_layered_blocks_replay_and_forwards_negatives(self):
        ad = LayeredAdapter(Config(console=False)); m, _ = legacy_score.score(ad, self.recs)
        self.assertEqual((m["TP"], m["FP"], m["FN"], m["TN"]), (1, 0, 0, 3))


class TestPreparedThroughProxy(unittest.TestCase):
    def test_replay_never_reaches_broker(self):
        tmp, T, recs, man = build_fixture(); self.addCleanup(tmp.cleanup)
        async def go():
            async with Rig() as r:
                c = await r.client("dev-csv"); n = 0
                for rec in recs:
                    p = rec["packet"]; c.send_raw(codec.build_publish(p["topic"], p["packet_id"], bytes.fromhex(p["payload_hex"]), 1, p["dup"])); n += 1
                    await c.writer.drain()
                    if rec["truth"] == "legit": await c.wait_for(lambda k=n: len(c.completed) >= k, 5)
                await c.wait_for(lambda: len(c.completed) >= n, 5); await r.settle(0.4)
                self.assertEqual(r.broker_received(), 3)                           # 3 negatives, replay dropped
                self.assertEqual([d["classification"] for d in r.decisions()], ["legit"] * 3 + ["replay"])
        asyncio.run(go())


if __name__ == "__main__":
    unittest.main(verbosity=2)
