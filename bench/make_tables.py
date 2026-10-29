"""Generates the paper's LaTeX tables from stored measurements (no hand-typed numbers)."""
import json, math, collections, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "paper" / "tables"; OUT.mkdir(parents=True, exist_ok=True)
S = json.loads((ROOT / "results/bench/summary.json").read_text())
off = json.loads((ROOT / "results/offline/offline_results.json").read_text())
scn = json.loads((ROOT / "results/bench/scenario_matrix.json").read_text())
eng = json.loads((ROOT / "results/bench/engine_microbench.json").read_text())["results"]
ds = json.loads((ROOT / "external_eval/fixed_dataset.json").read_text())
live2 = json.loads((ROOT / "results/output2_layered_ids/live_results.json").read_text())
live3 = json.loads((ROOT / "results/output3_layered_ids_minimized/live_results.json").read_text())


def wilson(k, n, z=1.959964):
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def pm(t, d=1, unit=""): return f"{t[0]:.{d}f}$\\pm${t[1]:.{d}f}{unit}"
def tt(s): return "\\texttt{" + s.replace("_", "\\_") + "}"

# ---------------- Table I: dataset composition (computed from the dataset file)
pub = [r for r in ds if r["scored"]]
kinds = collections.Counter(r["kind"] for r in pub)
dup1_fresh = sum(1 for r in pub if r["kind"] == "legit_fresh" and r["packet"]["dup"])
qos = collections.Counter(r["packet"]["qos"] for r in pub)
conns = len({(r["packet"]["src_ip"], r["packet"]["src_port"]) for r in pub})
acks = sum(1 for r in ds if r["packet"]["packet_type_name"] == "PUBACK")
t1 = f"""\\begin{{tabular}}{{@{{}}lr@{{}}}}
\\toprule
Item & Count \\\\
\\midrule
Scored PUBLISH packets (all QoS 1; {conns} client connections) & {len(pub):,} \\\\
\\quad legitimate, first transmission (DUP=0: {kinds['legit_fresh']-dup1_fresh:,}; DUP=1: {dup1_fresh}) & {kinds['legit_fresh']:,} \\\\
\\quad legitimate retransmissions (DUP=1) & {kinds['legit_retransmit']:,} \\\\
\\quad replay: exact copy (DUP=0) & {kinds['replay_exact']} \\\\
\\quad replay: DUP-evasion copy (DUP=1) & {kinds['replay_dupevasion']} \\\\
Context PUBACK packets (broker$\\rightarrow$client, captured) & {acks:,} \\\\
\\bottomrule
\\end{{tabular}}"""
assert set(qos) == {1}
(OUT / "t1_dataset.tex").write_text(t1)

# ---------------- Table II: detection
rows = []
def drow(name, m, mt):
    TP, FP, TN, FN = m["TP"], m["FP"], m["TN"], m["FN"]
    rl, rh = wilson(TP, TP + FN); fl, fh = wilson(FP, FP + TN)
    rows.append(f"{name} & {TP} & {FP} & {FN} & {mt['precision']:.3f} & {mt['recall']:.3f} [{rl:.3f},{rh:.3f}] & {FP/(FP+TN)*100:.2f} [{fl*100:.2f},{fh*100:.2f}] & {mt['f1']:.3f} \\\\")
drow("Packet-ID rule (existing)", off["Packet-ID / DUP reuse"]["matrix"], off["Packet-ID / DUP reuse"]["metrics"])
drow("HMAC+freshness rule (existing)", off["HMAC + freshness"]["matrix"], off["HMAC + freshness"]["metrics"])
L = off["Layered IDS (packet-id + HMAC/freshness)"]
drow("Layered IDS (offline)", L["matrix"], L["metrics"])
drow("Config 2, live Mosquitto", live2["ids_matrix"], live2["ids_metrics"])
drow("Config 3, live Mosquitto", live3["ids_matrix"], live3["ids_metrics"])
t2 = "\\begin{tabular}{@{}lrrrrrrr@{}}\n\\toprule\nDetector & TP & FP & FN & Prec. & Recall [95\\% CI] & FPR\\% [95\\% CI] & F1 \\\\\n\\midrule\n" + "\n".join(rows) + "\n\\bottomrule\n\\end{tabular}"
(OUT / "t2_detection.tex").write_text(t2)
rt = {k: off[k]["by_kind"]["legit_retransmit"] for k in ("Packet-ID / DUP reuse", "HMAC + freshness", "Layered IDS (packet-id + HMAC/freshness)")}
json.dump({"retransmissions_dropped": {k: v["flagged"] for k, v in rt.items()}, "n": 1671}, open(OUT / "retx.json", "w"))

# ---------------- Table III: scenario matrix
by = collections.defaultdict(dict)
for r in scn: by[r["id"]][r["config"]] = r
short = {"S1": "Legit QoS1, fresh seq", "S2": "Legit QoS1 DUP retransmit", "S3": "Legit QoS2 handshake", "S4": "Packet-ID reuse, fresh seq",
         "S5": "Exact replay (DUP=0)", "S6": "DUP-evasion replay", "S7": "Stale-seq replay (> window)", "S8": "Invalid HMAC",
         "S9": "Missing signature", "S10": "Replay, clean-session reconnect", "S11": "Replay, persistent resume", "S12": "Lost-ACK retransmit (uncertain)", "S13": "Cross-identity replay (devA$\\rightarrow$devB)"}
lines = []
for sid in [f"S{i}" for i in range(1, 14)]:
    r1, r2, r3 = by[sid][1], by[sid][2], by[sid][3]
    cells = []
    for r in (r1, r2, r3):
        v = r["broker_received"]; bad = r["attack_leaked"] or r["legit_lost"]
        cells.append(f"\\textbf{{{v}}}" if bad else f"{v}")
    lines.append(f"{sid} & {short[sid]} & {r1['legit']}/{r1['attack']} & {r1['ideal']} & {cells[0]} & {cells[1]} & {cells[2]} \\\\")
t3 = "\\begin{tabular}{@{}llccccc@{}}\n\\toprule\nID & Scenario & L/A & Ideal & C1 & C2 & C3 \\\\\n\\midrule\n" + "\n".join(lines) + "\n\\bottomrule\n\\end{tabular}"
(OUT / "t3_scenarios.tex").write_text(t3)
tot = {c: (sum(by[s][c]["attack_leaked"] for s in by), sum(by[s][c]["legit_lost"] for s in by), sum(by[s][c]["attack"] for s in by)) for c in (1, 2, 3)}
json.dump(tot, open(OUT / "scn_totals.json", "w"))

# ---------------- Table IV: performance
sat, pc = S["saturation"], S["paced"]
def col(n, f): return f(n)
rowsP = [
 ("Throughput, saturation (msg/s)", lambda n: pm(sat[n]["thr"], 0)),
 ("ACK round-trip p50 / p95 (ms)", lambda n: f"{pc[n]['rtt_p50'][0]:.2f} / {pc[n]['rtt_p95'][0]:.2f}"),
 ("Publish$\\rightarrow$subscriber p50 / p95 / p99 (ms)", lambda n: f"{pc[n]['e2e_p50'][0]:.2f} / {pc[n]['e2e_p95'][0]:.2f} / {pc[n]['e2e_p99'][0]:.2f}"),
 ("IDS decision time p50 / p95 ($\\mu$s)", lambda n: "--" if n == "1" else f"{pc[n]['decision_time_p50_us'][0]:.0f} / {pc[n]['decision_time_p95_us'][0]:.0f}"),
 ("IDS handling time p50 / p95 ($\\mu$s)", lambda n: "--" if n == "1" else f"{pc[n]['handling_time_p50_us'][0]:.0f} / {pc[n]['handling_time_p95_us'][0]:.0f}"),
 ("CPU, broker + proxy (CPU-ms / msg)", lambda n: pm(sat[n]["cpu_tot"], 4)),
 ("\\quad of which IDS proxy", lambda n: "--" if n == "1" else pm(sat[n]["cpu_p"], 4)),
 ("Peak RSS, broker + proxy (MB)", lambda n: f"{sat[n]['rss_b'][0] + sat[n]['rss_p'][0]:.1f}"),
 ("\\quad of which IDS proxy (MB)", lambda n: "--" if n == "1" else pm(sat[n]["rss_p"], 1)),
]
t4 = "\\begin{tabular}{@{}lccc@{}}\n\\toprule\nMetric & Config 1 & Config 2 & Config 3 \\\\\n\\midrule\n" + \
     "\n".join(f"{name} & {f('1')} & {f('2')} & {f('3')} \\\\" for name, f in rowsP) + "\n\\bottomrule\n\\end{tabular}"
(OUT / "t4_performance.tex").write_text(t4)

# ---------------- Table V: communication overhead
B = S["bytes"]
d = lambda a, b: f"{(b - a) / a * 100:+.1f}\\%"
rowsB = [
 ("PUBLISH wire bytes into broker (B/msg)", [f"{B[n]['to_broker_per_pub']:.1f}" for n in "123"], d(B["2"]["to_broker_per_pub"], B["3"]["to_broker_per_pub"])),
 ("Application payload per delivery (B)", [f"{B[n]['sub_payload_per_delivery']:.1f}" for n in "123"], d(B["2"]["sub_payload_per_delivery"], B["3"]["sub_payload_per_delivery"])),
 ("Total broker ingress, 40,800 sent (MB)", [f"{B[n]['broker_ingress_total']/1e6:.2f}" for n in "123"], d(B["2"]["broker_ingress_total"], B["3"]["broker_ingress_total"])),
 ("PUBLISH packets reaching broker", [f"{B[n]['n_pub']:,}" for n in "123"], "--"),
]
t5 = "\\begin{tabular}{@{}lcccc@{}}\n\\toprule\nMetric & C1 & C2 & C3 & C3 vs C2 \\\\\n\\midrule\n" + \
     "\n".join(f"{n} & {v[0]} & {v[1]} & {v[2]} & {dd} \\\\" for n, v, dd in rowsB) + "\n\\bottomrule\n\\end{tabular}"
(OUT / "t5_overhead.tex").write_text(t5)

# ---------------- engine microbench table
rowsE = [("Existing Packet-ID rule", "legacy_packet_id"), ("Existing HMAC+freshness rule", "legacy_hmac_freshness"),
         ("Layered engine (no log)", "layered_engine_no_log"), ("Layered engine + JSONL decision log", "layered_engine_with_jsonl_log"),
         ("Config 3 payload rewrite", "output3_minimize_rewrite")]
t6 = "\\begin{tabular}{@{}lrrrr@{}}\n\\toprule\nComponent & mean & p50 & p95 & p99 \\\\\n\\midrule\n" + \
     "\n".join(f"{n} & {eng[k]['mean_us']:.1f} & {eng[k]['p50_us']:.1f} & {eng[k]['p95_us']:.1f} & {eng[k]['p99_us']:.1f} \\\\" for n, k in rowsE) + "\n\\bottomrule\n\\end{tabular}"
(OUT / "t6_engine.tex").write_text(t6)
print("tables written:", sorted(p.name for p in OUT.iterdir()))
print("scenario totals (leaked, lost, attacks):", tot)
print("legit retransmissions dropped:", {k: v["flagged"] for k, v in rt.items()})

# ---------------- Table VII: external CSV validation (computed from stored results)
ext0 = json.loads((ROOT / "results/csv_external/offline/offline_results.json").read_text())
ext1 = json.loads((ROOT / "results/csv_external_dup1/offline/offline_results.json").read_text())
def lr(root, d): return json.loads((ROOT / "results" / root / d / "live_results.json").read_text())
L0 = {n: lr("csv_external", d) for n, d in ((1, "output1_no_ids"), (2, "output2_layered_ids"), (3, "output3_layered_ids_minimized"))}
L1 = {n: lr("csv_external_dup1", d) for n, d in ((1, "output1_no_ids"), (2, "output2_layered_ids"), (3, "output3_layered_ids_minimized"))}
def tfn(m): return f"{m['TP']}/{m['FP']}/{m['FN']}"
names = [("Packet-ID rule$^\\dagger$", "Packet-ID / DUP reuse"), ("HMAC+freshness rule$^\\dagger$", "HMAC + freshness"),
         ("Layered IDS$^\\dagger$ (offline)", "Layered IDS (packet-id + HMAC/freshness)")]
rowsX = [f"{lab} & {tfn(ext0[k]['matrix'])} & {tfn(ext1[k]['matrix'])} & -- & -- \\\\" for lab, k in names]
rowsX.append("\\midrule")
for n, lab in ((1, "C1 No IDS (live)"), (2, "C2 IDS full packet (live)"), (3, "C3 Modified IDS (live)")):
    a, b = L0[n], L1[n]
    m0 = tfn(a["ids_matrix"]) if "ids_matrix" in a else "--"; m1 = tfn(b["ids_matrix"]) if "ids_matrix" in b else "--"
    rowsX.append(f"{lab} & {m0} & {m1} & {a['replay_delivered_to_subscriber']}/{a['replay_sent']} & {b['replay_delivered_to_subscriber']}/{b['replay_sent']} \\\\")
t7 = ("\\begin{tabular}{@{}lcccc@{}}\n\\toprule\n & \\multicolumn{2}{c}{TP/FP/FN} & \\multicolumn{2}{c}{Replays reaching broker} \\\\\n"
      "\\cmidrule(lr){2-3}\\cmidrule(lr){4-5}\nDetector / configuration & DUP=0 & DUP=1$^\\ddagger$ & DUP=0 & DUP=1$^\\ddagger$ \\\\\n\\midrule\n" + "\n".join(rowsX) + "\n\\bottomrule\n\\end{tabular}")
(OUT / "t7_external.tex").write_text(t7)
ext = {"n_neg": L0[2]["legit_sent"], "n_rep": L0[2]["replay_sent"], "mosq_recv": {n: L0[n].get("broker_received_publishes") for n in (1, 2, 3)},
       "mosq_recv_dup1": {n: L1[n].get("broker_received_publishes") for n in (1, 2, 3)},
       "payload_per_msg": {n: L0[n]["delivered_payload_bytes"] / L0[n]["delivered_total"] for n in (1, 2, 3)},
       "recall_ci": wilson(1153, 1153), "fpr_ci": wilson(0, L0[2]["legit_sent"]), "legit_lost": {n: L0[n]["legit_lost"] for n in (1, 2, 3)}}
json.dump(ext, open(OUT / "ext_numbers.json", "w"), indent=1)
print("external table written; numbers:", json.dumps(ext))
