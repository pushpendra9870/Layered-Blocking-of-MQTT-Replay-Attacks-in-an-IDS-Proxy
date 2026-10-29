"""SYNTHETIC VARIANT (derived by us, not part of the supplied CSV/scripts): the same reconstructed replays with the
MQTT DUP flag set to 1 (the 'DUP-evasion' replay that defeats the original Packet-ID rule). Everything else is
identical to external_data/csv_replay_test_ready.json."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
src = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "external_data" / "csv_replay_test_ready.json"
dst = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "external_data" / "csv_replay_test_ready_dup1.json"
recs = json.loads(src.read_text()); n = 0
for r in recs:
    if r["truth"] == "replay":
        r["packet"]["dup"] = True; r["kind"] = "replay_csv_exact_dup1_SYNTHETIC_VARIANT"
        r["note"] = "SYNTHETIC VARIANT: DUP flag forced to 1 on a reconstructed replay."; n += 1
dst.write_text(json.dumps(recs, ensure_ascii=False, separators=(",", ":")))
print(f"wrote {dst} ({n} replay records with DUP=1)")
