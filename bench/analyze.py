"""Turns raw measurements into the paper's tables (LaTeX + JSON) and data figures.
Inputs : results/bench/raw_runs.jsonl, results/bench/engine_microbench.json, results/bench/scenario_matrix.json,
         results/offline/offline_results.json, results/offline/seq_window_sensitivity.json, results/output*/live_results.json
Outputs: ../paper/tables/*.tex, ../paper/figures/fig5..7 (pdf+png), results/bench/summary.json  -- nothing hand-typed."""
import json, math, statistics, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import stats

ROOT = Path(__file__).resolve().parent.parent
PAPER = ROOT / "paper"
RB = ROOT / "results" / "bench"
LAB = {1: "No IDS", 2: "IDS full packet", 3: "Modified IDS"}
COL = {1: "#8c8c8c", 2: "#3b6fb6", 3: "#d98324"}
HAT = {1: "", 2: "//", 3: "xx"}
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7, "axes.linewidth": 0.6, "pdf.fonttype": 42,
                     "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False,
                     "xtick.major.width": 0.6, "ytick.major.width": 0.6})


def wilson(k, n, z=1.959964):
    if n == 0: return (float("nan"), float("nan"))
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


def tci(xs, conf=0.95):
    xs = list(xs); n = len(xs)
    m = statistics.fmean(xs)
    if n < 2: return m, 0.0, 0.0
    sd = statistics.stdev(xs); h = stats.t.ppf((1 + conf) / 2, n - 1) * sd / math.sqrt(n)
    return m, sd, h


def pct(xs, f):
    s = sorted(xs); return s[min(len(s) - 1, int(f * len(s)))]


def fmt(m, sd, d=1): return f"{m:.{d}f} $\\pm$ {sd:.{d}f}"


def save(fig, name):
    for ext in ("pdf", "png"):
        fig.savefig(PAPER / "figures" / f"{name}.{ext}", dpi=300, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


def main():
    runs = [json.loads(l) for l in open(RB / "raw_runs.jsonl")]
    meta = json.loads((RB / "meta.json").read_text()) if (RB / "meta.json").exists() else {}
    S = {n: [r for r in runs if r["config"] == n and r["mode"] == "saturation"] for n in (1, 2, 3)}
    P = {n: [r for r in runs if r["config"] == n and r["mode"] == "paced"] for n in (1, 2, 3)}
    summ = {"meta": meta, "n_reps": {n: len(S[n]) for n in S}}

    # ---------------------------------------------------- saturation: throughput, CPU, memory
    sat = {}
    for n in (1, 2, 3):
        thr, thr_del, cpu_b, cpu_p, rss_b, rss_p, wall = [], [], [], [], [], [], []
        for r in S[n]:
            tot = r["legit_sent"] + r["replay_sent"]
            thr.append(tot / r["t_total_s"]); thr_del.append(r["delivered"] / r["t_total_s"])
            cb = r["resources"]["broker"]["cpu_s"]; cp = r["resources"].get("proxy", {}).get("cpu_s", 0.0)
            cpu_b.append(1000 * cb / tot); cpu_p.append(1000 * cp / tot)
            rss_b.append(r["resources"]["broker"]["rss_peak_mb"]); rss_p.append(r["resources"].get("proxy", {}).get("rss_peak_mb", 0.0))
            wall.append(r["t_total_s"])
        sat[n] = dict(thr=tci(thr), thr_del=tci(thr_del), cpu_b=tci(cpu_b), cpu_p=tci(cpu_p),
                      cpu_tot=tci([a + b for a, b in zip(cpu_b, cpu_p)]), rss_b=tci(rss_b), rss_p=tci(rss_p), wall=tci(wall),
                      n_msgs=S[n][0]["legit_sent"] + S[n][0]["replay_sent"], leaked=[r["replay_leaked"] for r in S[n]],
                      lost=[r["legit_lost"] for r in S[n]], all_acked=all(r["all_acked"] for r in S[n]),
                      rss_p_base=statistics.fmean(r["resources"].get("proxy", {}).get("rss_base_mb", 0) for r in S[n]))
    summ["saturation"] = {n: {k: v for k, v in d.items()} for n, d in sat.items()}

    # ---------------------------------------------------- paced: latency + processing time
    lat = {}
    for n in (1, 2, 3):
        rtt = [x for r in P[n] for x in r["ack_rtt_s"]]; e2e = [x for r in P[n] for x in r["e2e_s"]]
        per = lambda key, f: [pct(r[key], f) * 1e3 for r in P[n]]
        lat[n] = dict(rtt=np.array(rtt) * 1e3, e2e=np.array(e2e) * 1e3,
                      rtt_p50=tci(per("ack_rtt_s", .5)), rtt_p95=tci(per("ack_rtt_s", .95)), rtt_p99=tci(per("ack_rtt_s", .99)),
                      e2e_p50=tci(per("e2e_s", .5)), e2e_p95=tci(per("e2e_s", .95)), e2e_p99=tci(per("e2e_s", .99)),
                      n_rtt=len(rtt), n_e2e=len(e2e), rate=statistics.fmean(r["achieved_offered_rate"] for r in P[n]),
                      leaked=[r["replay_leaked"] for r in P[n]], lost=[r["legit_lost"] for r in P[n]])
        if n > 1:
            for key in ("decision_time", "handling_time"):
                for q in ("p50_us", "p95_us", "p99_us", "mean_us"):
                    lat[n][f"{key}_{q}"] = tci([r["proxy_stats"][key][q] for r in P[n]])
        lat[n]["cpu_tot_paced"] = tci([(r["resources"]["broker"]["cpu_s"] + r["resources"].get("proxy", {}).get("cpu_s", 0)) / (r["legit_sent"] + r["replay_sent"]) * 1000 for r in P[n]])
    summ["paced"] = {n: {k: (v.tolist()[:0] if isinstance(v, np.ndarray) else v) for k, v in d.items()} for n, d in lat.items()}

    # ---------------------------------------------------- bytes (communication overhead)
    byt = {}
    r2, r3 = S[2][0], S[3][0]
    tot_msgs = r2["legit_sent"] + r2["replay_sent"]
    c2, c3 = r2["proxy_stats"]["counters"], r3["proxy_stats"]["counters"]
    full_pub = c2["bytes_publish_in"] / tot_msgs            # average full PUBLISH packet from clients
    for n, rr in ((1, S[1]), (2, S[2]), (3, S[3])):
        r = rr[0]
        ingress = {1: c2["bytes_publish_in"], 2: c2["bytes_publish_out"], 3: c3["bytes_publish_out"]}[n]
        npub = {1: tot_msgs, 2: c2["forwarded_publish"], 3: c3["forwarded_publish"]}[n]
        byt[n] = dict(pub_in_per_msg=full_pub, to_broker_per_pub=ingress / npub, broker_ingress_total=ingress, n_pub=npub,
                      sub_rx_per_delivery=r["observer_rx_bytes"] / r["delivered"], sub_payload_per_delivery=r["observer_payload_bytes"] / r["delivered"],
                      delivered=r["delivered"])
    byt["synthetic"] = dict(acks=c2["synthetic_acks"], bytes=c2["bytes_to_clients_synthetic"],
                            per_ack=c2["bytes_to_clients_synthetic"] / max(1, c2["synthetic_acks"]),
                            dropped=c2["dropped"])
    summ["bytes"] = byt

    # ---------------------------------------------------- engine microbench
    eng = json.loads((RB / "engine_microbench.json").read_text())["results"] if (RB / "engine_microbench.json").exists() else None
    summ["engine"] = eng

    # ---------------------------------------------------- detection (offline + live)
    off = json.loads((ROOT / "results" / "offline" / "offline_results.json").read_text())
    det = {"Packet-ID rule (existing)": off["Packet-ID / DUP reuse"], "HMAC rule (existing)": off["HMAC + freshness"],
           "Layered IDS": off["Layered IDS (packet-id + HMAC/freshness)"]}
    summ["detection_offline"] = {k: v["matrix"] | v["metrics"] for k, v in det.items()}
    live = {n: json.loads((ROOT / "results" / d / "live_results.json").read_text())
            for n, d in ((1, "output1_no_ids"), (2, "output2_layered_ids"), (3, "output3_layered_ids_minimized"))}
    summ["live_main"] = {n: {k: v for k, v in r.items() if not isinstance(v, (dict, list)) or k in ("ids_matrix", "ids_metrics")} for n, r in live.items()}
    (RB / "summary.json").write_text(json.dumps(summ, indent=1, default=float))

    # ================================================================ FIGURES
    # ---- Fig 5: detection quality + window sensitivity
    sens = json.loads((ROOT / "results" / "offline" / "seq_window_sensitivity.json").read_text())
    fig, axs = plt.subplots(1, 3, figsize=(7.16, 1.92), gridspec_kw={"width_ratios": [1.25, 0.9, 1.1], "wspace": 0.42})
    ax = axs[0]
    names = list(det.keys()); mets = ["precision", "recall", "f1"]
    x = np.arange(len(mets)); w = 0.26
    for i, nm in enumerate(names):
        vals = [det[nm]["metrics"][m] for m in mets]
        ax.bar(x + (i - 1) * w, vals, w, color=["#b9b9b9", "#9fc3e8", "#3b6fb6"][i], edgecolor="#222", lw=0.5,
               hatch=["", "..", "//"][i], label=nm)
        for xi, v in zip(x + (i - 1) * w, vals):
            ax.text(xi, v + 0.015, f"{v:.2f}", ha="center", fontsize=5.4)
    ax.set_xticks(x); ax.set_xticklabels(["Precision", "Recall", "F1"]); ax.set_ylim(0, 1.62); ax.set_yticks([0, .25, .5, .75, 1.0])
    ax.set_ylabel("score (offline, 4080 PUBLISH)"); ax.legend(fontsize=5.6, loc="upper center", ncol=1, bbox_to_anchor=(0.5, 1.0))
    ax.set_title("(a) Detection quality", fontsize=7, pad=3)
    ax = axs[1]
    leak = [live[n]["replay_delivered_to_subscriber"] for n in (1, 2, 3)]
    bars = ax.bar(range(3), leak, color=[COL[n] for n in (1, 2, 3)], edgecolor="#222", lw=0.5)
    for b, n in zip(bars, (1, 2, 3)): b.set_hatch(HAT[n])
    for i, v in enumerate(leak): ax.text(i, v + 1.5, f"{v}/80", ha="center", fontsize=6)
    ax.set_xticks(range(3)); ax.set_xticklabels(["No\nIDS", "IDS full\npacket", "Modified\nIDS"], fontsize=6)
    ax.set_ylim(0, 100); ax.set_ylabel("replays delivered (of 80)")
    ax.set_title("(b) Replays reaching\nbroker/subscriber", fontsize=7, pad=3)
    ax = axs[2]
    ws = [s["seq_window"] for s in sens]; fp = [s["FP"] for s in sens]; rc = [s["recall"] for s in sens]
    ax.plot(ws, fp, "o-", color="#a02020", ms=3, lw=1.0, label="false positives")
    ax.set_xscale("log"); ax.set_xlabel("seq_window"); ax.set_ylabel("false positives (legit dropped)", color="#a02020")
    ax.axvline(179, color="#555", ls=":", lw=0.8); ax.text(190, 520, "179: first FP-free\nwindow", fontsize=5.4, color="#444")
    ax2 = ax.twinx(); ax2.spines["right"].set_visible(True); ax2.plot(ws, rc, "s--", color="#3b6fb6", ms=2.5, lw=0.8)
    ax2.set_ylim(0, 1.15); ax2.set_ylabel("recall", color="#3b6fb6")
    ax.set_title("(c) seq_window sensitivity", fontsize=7, pad=3)
    save(fig, "fig5_detection")

    # ---- Fig 6: latency CDFs + processing time
    fig, axs = plt.subplots(1, 3, figsize=(7.16, 1.95), gridspec_kw={"wspace": 0.38})
    for ax, key, ttl in ((axs[0], "rtt", "(a) PUBLISH$\\rightarrow$PUBACK latency"), (axs[1], "e2e", "(b) publish$\\rightarrow$subscriber latency")):
        for n in (1, 2, 3):
            v = np.sort(lat[n][key]); y = np.arange(1, len(v) + 1) / len(v)
            ax.plot(v, y, color=COL[n], lw=1.2, ls=["-", "--", "-."][n - 1], label=LAB[n])
        ax.set_xscale("log"); ax.set_xlabel("latency (ms)"); ax.set_ylabel("CDF"); ax.set_ylim(0, 1.02)
        ax.set_title(ttl, fontsize=7, pad=3)
    axs[0].legend(fontsize=6, loc="lower right")
    ax = axs[2]
    labs = ["decision\n(detector)", "handling\n(parse+decide+write)"]
    x = np.arange(2); w = 0.19
    for i, n in enumerate((2, 3)):
        for j, (q, al) in enumerate((("p50", 1.0), ("p95", 0.45))):
            vals = [lat[n][f"decision_time_{q}_us"][0], lat[n][f"handling_time_{q}_us"][0]]
            off = (i * 2 + j - 1.5) * w
            ax.bar(x + off, vals, w, color=COL[n], alpha=al, edgecolor="#222", lw=0.5, hatch=HAT[n])
            for xi, v in zip(x + off, vals):
                ax.text(xi, v + 8, f"{v:.0f}", ha="center", fontsize=4.8, rotation=90, va="bottom")
    ax.set_xticks(x); ax.set_xticklabels(labs, fontsize=6); ax.set_ylabel("per-PUBLISH time ($\\mu$s)"); ax.set_ylim(0, 700)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(fc=COL[2], ec="#222", hatch=HAT[2], label="IDS full packet"), Patch(fc=COL[3], ec="#222", hatch=HAT[3], label="Modified IDS"),
                       Patch(fc="#999", ec="#222", label="solid = p50, light = p95")], fontsize=5.2, loc="upper left")
    ax.set_title("(c) IDS processing time", fontsize=7, pad=3)
    save(fig, "fig6_latency")

    # ---- Fig 7: throughput / CPU / memory / bytes
    fig, axs = plt.subplots(1, 4, figsize=(7.16, 1.9), gridspec_kw={"wspace": 0.55})
    ax = axs[0]
    for n in (1, 2, 3):
        m, sd, h = sat[n]["thr"]
        ax.bar(n - 1, m, 0.62, yerr=h, color=COL[n], edgecolor="#222", lw=0.5, hatch=HAT[n], capsize=2, error_kw={"lw": 0.7})
        ax.text(n - 1, m + h + 300, f"{m:,.0f}", ha="center", fontsize=5.6)
    ax.set_xticks(range(3)); ax.set_xticklabels(["No\nIDS", "IDS\nfull", "Modif.\nIDS"], fontsize=6)
    ax.set_ylabel("messages / s (saturation)"); ax.set_ylim(0, sat[1]["thr"][0] * 1.2); ax.set_title("(a) Throughput", fontsize=7, pad=3)
    ax = axs[1]
    for n in (1, 2, 3):
        b, p = sat[n]["cpu_b"][0], sat[n]["cpu_p"][0]
        ax.bar(n - 1, b, 0.62, color="#bcd2ee", edgecolor="#222", lw=0.5, label="broker" if n == 1 else None)
        ax.bar(n - 1, p, 0.62, bottom=b, color=COL[n], edgecolor="#222", lw=0.5, hatch=HAT[n], label="IDS proxy" if n == 2 else None)
        ax.errorbar(n - 1, b + p, yerr=sat[n]["cpu_tot"][2], color="#111", capsize=2, lw=0.7)
        ax.text(n - 1, b + p + sat[n]["cpu_tot"][2] + 0.01 * (b + p), f"{b+p:.3f}", ha="center", fontsize=5.6)
    ax.set_xticks(range(3)); ax.set_xticklabels(["No\nIDS", "IDS\nfull", "Modif.\nIDS"], fontsize=6)
    ax.set_ylabel("CPU-ms per message"); ax.set_title("(b) CPU cost", fontsize=7, pad=3); ax.legend(fontsize=5.4, loc="upper left")
    ax = axs[2]
    for n in (1, 2, 3):
        b, p = sat[n]["rss_b"][0], sat[n]["rss_p"][0]
        ax.bar(n - 1, b, 0.62, color="#bcd2ee", edgecolor="#222", lw=0.5)
        ax.bar(n - 1, p, 0.62, bottom=b, color=COL[n], edgecolor="#222", lw=0.5, hatch=HAT[n])
        ax.text(n - 1, b + p + 1, f"{b+p:.0f}", ha="center", fontsize=5.6)
    ax.set_xticks(range(3)); ax.set_xticklabels(["No\nIDS", "IDS\nfull", "Modif.\nIDS"], fontsize=6)
    ax.set_ylabel("peak RSS (MB)"); ax.set_title("(c) Memory", fontsize=7, pad=3)
    ax = axs[3]
    vals = [byt[n]["to_broker_per_pub"] for n in (1, 2, 3)]
    for n, v in zip((1, 2, 3), vals):
        ax.bar(n - 1, v, 0.62, color=COL[n], edgecolor="#222", lw=0.5, hatch=HAT[n])
        ax.text(n - 1, v + 2, f"{v:.0f} B", ha="center", fontsize=5.6)
    ax.set_xticks(range(3)); ax.set_xticklabels(["No\nIDS", "IDS\nfull", "Modif.\nIDS"], fontsize=6)
    ax.set_ylabel("wire bytes / PUBLISH to broker"); ax.set_ylim(0, 470); ax.set_title("(d) Broker ingress", fontsize=7, pad=3)
    save(fig, "fig7_resources")
    print("analysis done")


if __name__ == "__main__":
    main()
