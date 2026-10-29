#!/usr/bin/env python3
"""Prepare an MQTT test dataset from the external replay-attack CSV.

Place this file in the mqtt_real_dataset_eval project root. It converts CSV rows
into the JSON schema expected by eval/live_eval.py. The CSV is NOT a packet
capture, so MQTT fields absent from the source are explicitly synthesized.

Only attack-labeled rows whose topic + payload match an earlier non-attack-labeled
row are reconstructed as exact replays. Unmatched attack-labeled rows are excluded
from the scored replay set rather than silently inventing an original message.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
EXTERNAL_DIR = ROOT / "external_eval"
if str(EXTERNAL_DIR) not in sys.path:
    sys.path.insert(0, str(EXTERNAL_DIR))

try:
    from signing import build_signed_payload
except ImportError as exc:  # pragma: no cover - clearer setup error
    raise SystemExit(
        "Could not import external_eval/signing.py. Put this script in the "
        "mqtt_real_dataset_eval project root."
    ) from exc

ATTACK_LABEL = "replay attack"
BROKER_PORT = 1883
SRC_IP = "192.0.2.10"   # documentation-only TEST-NET address; local evaluator uses loopback
DST_IP = "192.0.2.20"


def parse_timestamp(value: str) -> datetime:
    value = (value or "").strip()
    if not value:
        raise ValueError("empty timestamp")
    # The source file uses ISO timestamps without a timezone. Preserve its order;
    # the epoch field below is only evaluator metadata, not a claim about timezone.
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def timestamp_number(dt: datetime) -> float:
    # Naive timestamps are interpreted by Python in the machine's local timezone.
    # This field is not used for ground-truth labels or detector verdicts.
    return dt.timestamp()


def load_csv(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"uuid", "timestamp", "topic", "payload", "tipo_ataque"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise SystemExit(f"CSV is missing required columns: {', '.join(sorted(missing))}")
        for row_number, row in enumerate(reader, start=2):
            try:
                dt = parse_timestamp(row.get("timestamp", ""))
            except (ValueError, TypeError) as exc:
                raise SystemExit(f"Invalid timestamp at CSV line {row_number}: {exc}") from exc
            row["_row_number"] = row_number
            row["_dt"] = dt
            row["_timestamp_num"] = timestamp_number(dt)
            row["_topic"] = (row.get("topic") or "").strip()
            row["_payload"] = row.get("payload") or ""
            row["_label"] = (row.get("tipo_ataque") or "").strip().casefold()
            if not row["_topic"]:
                raise SystemExit(f"Empty topic at CSV line {row_number}")
            rows.append(row)
    # Stable sort: retain original row order for equal timestamps.
    rows.sort(key=lambda r: (r["_dt"], r["_row_number"]))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", default=str(ROOT / "external_data" / "replay_attack.csv"),
                    help="Input CSV (default: external_data/replay_attack.csv)")
    ap.add_argument("--out", default=str(ROOT / "external_data" / "csv_replay_test_ready.json"),
                    help="Output JSON dataset consumed by the three existing runners")
    ap.add_argument("--manifest", default=str(ROOT / "external_data" / "csv_replay_manifest.json"),
                    help="Write conversion notes, counts and limitations here")
    ap.add_argument("--max-legit", type=int, default=0,
                    help="Optional cap on background non-attack-labeled rows (0 = all); source rows needed by selected replays are added as needed.")
    ap.add_argument("--max-replay", type=int, default=0,
                    help="Optional cap on matched replay rows (0 = all matched rows). For quick smoke tests.")
    args = ap.parse_args()

    csv_path = Path(args.csv).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()
    if not csv_path.is_file():
        raise SystemExit(f"CSV not found: {csv_path}\nPass its path with --csv.")
    if args.max_legit < 0 or args.max_replay < 0:
        raise SystemExit("--max-legit and --max-replay must be zero (all) or positive.")

    rows = load_csv(csv_path)
    topics = sorted({r["_topic"] for r in rows})
    # A separate synthetic client/connection per topic makes each topic's sequence
    # monotonic and avoids claiming the CSV contains original client/session IDs.
    topic_port = {topic: 41000 + i for i, topic in enumerate(topics)}
    topic_seq: defaultdict[str, int] = defaultdict(int)
    latest_original: dict[tuple[str, str], dict[str, Any]] = {}
    legit_records: list[dict[str, Any]] = []
    replay_records: list[dict[str, Any]] = []
    excluded_replays: list[dict[str, Any]] = []
    attack_rows = 0
    non_attack_rows = 0
    other_label_rows: list[dict[str, Any]] = []

    for row in rows:
        topic = row["_topic"]
        payload_text = row["_payload"]
        key = (topic, payload_text)
        row_number = row["_row_number"]
        uuid = row.get("uuid", "")
        ts_num = row["_timestamp_num"]

        if row["_label"] == ATTACK_LABEL:
            attack_rows += 1
            source = latest_original.get(key)
            if source is None:
                excluded_replays.append({
                    "csv_line": row_number,
                    "uuid": uuid,
                    "topic": topic,
                    "reason": "No earlier non-attack-labeled row with exactly the same topic and payload; cannot reconstruct an exact replay without inventing its original.",
                })
                continue
            packet = dict(source["packet"])
            # The replay's transport timestamp is new; its signed application payload,
            # sequence and packet ID remain copied from the earlier original message.
            packet["timestamp"] = f"{ts_num:.6f}"
            packet["dup"] = False  # DUP flag is absent from CSV; controlled DUP=0 test variant.
            replay_records.append({
                "kind": "replay_csv_exact_dup0",
                "truth": "replay",
                "scored": True,
                "packet": packet,
                "index": -1,
                "note": "Reconstructed exact replay: reused a prior signed payload and packet ID; DUP=0 is synthesized because CSV has no MQTT flags.",
                "source_csv_line": source["csv_line"],
                "csv_line": row_number,
                "source_uuid": source["uuid"],
                "uuid": uuid,
            })
            continue

        if row["_label"] != "":
            # INTEGRATION GUARD (not in the original script): an unrecognised non-blank label is neither a
            # replay we can reconstruct nor a verified negative, so it is excluded and reported.
            other_label_rows.append({"csv_line": row_number, "uuid": uuid, "label": row["_label"]})
            continue
        # Blank tipo_ataque values are not explicit benign labels. They are used as
        # non-attack-labeled negatives for this experiment, documented in the manifest.
        non_attack_rows += 1
        topic_seq[topic] += 1
        seq = topic_seq[topic]
        pid = ((seq - 1) % 65535) + 1
        original_ts = row["timestamp"].strip()
        app_data = {"raw": payload_text}
        signed_payload = build_signed_payload(topic, app_data, seq, original_ts)
        packet = {
            "src_ip": SRC_IP,
            "dst_ip": DST_IP,
            "src_port": topic_port[topic],
            "dst_port": BROKER_PORT,
            "packet_type_id": 3,
            "packet_type_name": "PUBLISH",
            "client_id": "",
            "topic": topic,
            "payload_hex": signed_payload.hex(),
            "qos": 1,
            "retain": False,
            "dup": False,
            "packet_id": pid,
            "timestamp": f"{ts_num:.6f}",
        }
        rec = {
            "kind": "legit_fresh",
            "truth": "legit",
            "scored": True,
            "packet": packet,
            "index": -1,
            "note": "Non-attack-labeled CSV row wrapped in a synthetic valid HMAC envelope; original MQTT QoS/PID/flags were not present in CSV.",
            "csv_line": row_number,
            "uuid": uuid,
        }
        legit_records.append(rec)
        # Save the most recent earlier source for this exact topic+payload.
        latest_original[key] = {"packet": packet, "csv_line": row_number, "uuid": uuid}

    # Optional caps are deterministic. For a useful smoke test, select replay cases
    # first, then retain their original source rows even if they fall outside the first
    # max-legit rows. Thus max-legit caps the background sample, while necessary source
    # rows may be added on top so every selected replay has a valid original.
    if args.max_replay:
        replay_records = replay_records[:args.max_replay]
    if args.max_legit:
        selected = {r["csv_line"]: r for r in legit_records[:args.max_legit]}
        by_line = {r["csv_line"]: r for r in legit_records}
        for replay in replay_records:
            source_line = replay["source_csv_line"]
            if source_line in by_line:
                selected[source_line] = by_line[source_line]
        legit_records = sorted(selected.values(), key=lambda r: r["csv_line"])

    output_records = legit_records + replay_records
    for i, record in enumerate(output_records):
        record["index"] = i

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output_records, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    replay_by_topic = defaultdict(int)
    legit_by_topic = defaultdict(int)
    for r in legit_records:
        legit_by_topic[r["packet"]["topic"]] += 1
    for r in replay_records:
        replay_by_topic[r["packet"]["topic"]] += 1

    manifest = {
        "source_csv": str(csv_path),
        "prepared_dataset": str(out_path),
        "source_rows": len(rows),
        "non_attack_labeled_rows_used_as_negative_class": len(legit_records),
        "attack_labeled_replay_rows": attack_rows,
        "matched_replay_rows_scored": len(replay_records),
        "attack_labeled_rows_excluded_as_unmatched": len(excluded_replays),
        "rows_excluded_unrecognised_label": len(other_label_rows),
        "excluded_replay_examples": excluded_replays[:50],
        "excluded_replay_count_full": len(excluded_replays),
        "topic_counts_legit": dict(legit_by_topic),
        "topic_counts_matched_replay": dict(replay_by_topic),
        "synthetic_fields_and_assumptions": [
            "The CSV is not a PCAP and does not provide MQTT packet IDs, QoS, DUP/RETAIN flags, MQTT session IDs, or ACK exchanges.",
            "A separate synthetic MQTT client/connection is assigned per topic.",
            "QoS 1, packet IDs, and DUP=0 are synthesized for the controlled test.",
            "Non-attack-labeled rows have blank tipo_ataque; they are treated as negatives but are not independently verified benign labels.",
            "Only replay-labeled rows matching an earlier non-attack-labeled row on exact topic+payload are scored as exact replays.",
            "CSV payloads are wrapped in a valid HMAC envelope using the project's existing signing.py and MQTT_HMAC_SECRET.",
            "The existing evaluator sends all non-attack-labeled rows first, then the reconstructed replay rows. This is a controlled replay-after-original test, not a timing-faithful reproduction of the original campaign.",
            "The original signed envelope is reused for a replay, so the replay has the same signed data/sequence and packet ID as its matched original.",
        ],
        "replay_exclusions": excluded_replays,
        "caps": {"max_legit_background_sample": args.max_legit, "max_replay": args.max_replay,
                  "note": "When --max-legit is set, original rows needed by selected replay cases are retained in addition to the capped background sample."},
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print("Prepared external CSV evaluation dataset")
    print(f"  Source rows                         : {len(rows)}")
    print(f"  Non-attack-labeled records included : {len(legit_records)}")
    print(f"  Replay-labeled rows in source       : {attack_rows}")
    print(f"  Matched exact replays scored        : {len(replay_records)}")
    print(f"  Replay-labeled rows excluded        : {len(excluded_replays)}")
    print(f"  Rows excluded (unrecognised label)  : {len(other_label_rows)}")
    print(f"  Total scored records                : {len(output_records)}")
    print(f"  JSON                                : {out_path}")
    print(f"  Manifest                            : {manifest_path}")
    print("\nRead the manifest before reporting results: this is reconstructed MQTT traffic, not a raw-PCAP replay.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
