# Layered MQTT Replay IDS (proxy) — extension of `mqtt_real_dataset_eval`

Combines the two existing replay detectors (`PacketIdReuseRule`, `HmacFreshnessRule`) into one
**layered IDS that runs as a TCP proxy** between MQTT clients and a broker, and ships three
independently runnable configurations. Scope is **replay attacks only** (no Keep-Alive abuse,
DoS or ML detection).

> **Status honesty.** **Every live run and every socket test below used a real Mosquitto 2.0.18 broker**
> (each runner starts its own private Mosquitto; broker-side counts come from Mosquitto's own debug log).
> Executed on **Linux (Ubuntu 24.04, Python 3.12.3)**. The Windows 11 commands in §2 were **not executed on
> Windows** by me; the code uses only portable `asyncio`/`subprocess`/`pathlib` and no third-party runtime
> package, but treat §2 as untested until you run it once. The bundled `mini_broker.py` is only a
> zero-install fallback (`--broker mini`), not the basis of any reported result.
> Two things involve no broker by nature: the 30 engine unit tests and the offline scoring (§5.1).

## 1. What was inspected (actual files)

| Item | File | Finding |
|---|---|---|
| Packet-ID rule | `external_eval/detectors.py::PacketIdReuseRule` | flags an ACKed id reused with **DUP=0 only**; keyed by `(ip,port)`; wall-clock time; no QoS2/session state |
| HMAC rule | `external_eval/detectors.py::HmacFreshnessRule` | HMAC-SHA256 verify + **strictly increasing** seq per connection |
| Signing | `external_eval/signing.py` | HMAC over `topic\|data\|seq\|ts`; payload `{data,seq,ts,sig}`; key from `MQTT_HMAC_SECRET` |
| Dataset | `external_eval/fixed_dataset.json` (+`legit_base.json`, pcap) | 4,000 real captured PUBLISH (2,329 fresh, 1,671 retransmit), 15,000 real PUBACK context, 80 synthetic replays |
| Replay generator / scoring | `attacker_replay.py`, `score.py` | reused unchanged (`score()`/`metrics()` also score the new pipeline) |
| Original results | `external_eval/results/*` | **untouched** (sha256 verified, §7) and reproduced exactly |

Why neither rule alone is enough (measured on the real data, offline): Packet-ID rule recall **0.50**
(blind to DUP=1 evasion); HMAC rule precision **0.094** (770 false positives, all real retransmissions
whose seq is not above the highest). The layered engine fixes both (§4).

## 2. Windows 11 setup and execution (PowerShell)

Requirements: Python 3.10+ from python.org (tested on 3.12 on Linux) and **Mosquitto 2.x** (installer from
mosquitto.org; default path `C:\Program Files\mosquitto\mosquitto.exe` is auto-detected, otherwise set
`$env:MOSQUITTO_EXE`). **No pip packages are needed.** `scapy` is only needed to rebuild datasets from the pcap.
You do not start Mosquitto yourself for the runners/tests: they launch a private loopback instance (own config,
port and log) and stop it afterwards.

```powershell
cd C:\path\to\mqtt_real_dataset_eval
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1          # if blocked:  Set-ExecutionPolicy -Scope Process Bypass
python --version

# optional: shared HMAC key (must be identical for signer and IDS; default = lab key from signing.py)
$env:MQTT_HMAC_SECRET = "your-secret"

& "C:\Program Files\mosquitto\mosquitto.exe" -h           # confirm Mosquitto is installed (prints version)

# tests (52; socket tests use a fresh Mosquitto per test)
python -m unittest discover -s tests -t . -v

# the three configurations, each self-contained (starts broker [+ proxy], replays the dataset, stops)
python run_output1_no_ids.py
python run_output2_layered_ids.py
python run_output3_layered_ids_minimized.py
python run_all.py                      # EVERYTHING on Mosquitto: tests, 3 outputs, new_conn, 2nd window, equivalence
```

Ports used (loopback only): broker 18830, proxy 18840. Change with `--broker-port/--proxy-port`.
No Mosquitto? `--broker mini` (or `python run_all.py --broker mini`) uses the bundled test broker instead.
Replay variant where the attacker reconnects with the victim's client-id: add `--replay-mode new_conn`.

**Manual, three terminals** (to point your own clients at the IDS). Save `mosq.conf`:
```
listener 1883 127.0.0.1
allow_anonymous true
max_queued_messages 0
max_inflight_messages 0
```
```powershell
& "C:\Program Files\mosquitto\mosquitto.exe" -c mosq.conf -v                                        # T1 broker
python -m replay_ids.proxy --config configs\output2_layered_ids.json --listen-port 1884 --broker-port 1883 --decision-log results\manual_decisions.jsonl   # T2 (Output 3: configs\output3_layered_ids_minimized.json --app-feed results\manual_feed.jsonl)
python -m replay_ids.consumer_min --port 1883 --topic "#" --feed results\manual_feed.jsonl            # T3 (Output 3 consumer)
```
Your clients then connect to **port 1884** instead of 1883. (Against an already-running broker the evaluator also
accepts `--broker external --broker-port N`.)

## 3. The three configurations

| | Entry point | Config | Behaviour |
|---|---|---|---|
| **Output 1** No IDS | `run_output1_no_ids.py` | `configs/output1_no_ids.json` | client → broker directly; nothing filtered; measures delivery + replay leakage |
| **Output 2** Layered IDS | `run_output2_layered_ids.py` | `configs/output2_layered_ids.json` | client → proxy → broker; both detectors in one pipeline; confirmed replays **not written to the broker socket** |
| **Output 3** + minimized data | `run_output3_layered_ids_minimized.py` | `configs/output3_layered_ids_minimized.json` | identical detection (`minimize:true` is the only difference); after verification the PUBLISH payload becomes `{"client_id","message"}` |

Detectors are one shared implementation (`replay_ids/engine.py`); the outputs differ only by config.

**Output 3 specifics.** The forwarded packet is still a valid MQTT PUBLISH (same topic, QoS, packet id, flags;
remaining-length re-encoded). `sig`, `seq`, `ts`, digest never leave the IDS. **Keep Alive is connection metadata,
not a PUBLISH field**, so it is delivered in `app_feed.jsonl` (`session` record at CONNECT and in each `message`
record) and merged by `replay_ids/consumer_min.py`. CONNECT/CONNACK/acks are untouched.
Demo output: `results/output3_layered_ids_minimized/consumer_demo.txt`.

## 4. Detection logic (packet-id state × HMAC/freshness)

Per client-id (from CONNECT) the engine keeps: accepted `seq → content digest` (bounded by `seq_window`),
highest seq, and packet-id transactions (`in_flight → await_pubrel → await_pubcomp → completed`), updated from
the **ACKs actually relayed** by the proxy. Flow diagrams: `docs/ARCHITECTURE.md`.

| Situation | Verdict | Action | Reason code |
|---|---|---|---|
| Unsigned / malformed envelope | invalid | **drop** (`on_missing_signature`) | `missing_signature` |
| HMAC fails | invalid | **drop** (`on_invalid_hmac`); does not consume the seq | `invalid_hmac` |
| seq older than `highest − seq_window` | replay | drop | `replay_stale_sequence` |
| seq already accepted, ACK/COMP relayed (txn **completed**) | replay | drop | `replay_completed_transaction` |
| seq already accepted, same content, txn **in flight**, DUP=1 | legit | forward | `retransmit_inflight` |
| seq already accepted, txn in flight, DUP=0 | replay | drop | `replay_duplicate_inflight_nodup` |
| seq accepted, no txn explains it / different content | replay | drop | `replay_seq_already_accepted` / `replay_seq_content_mismatch` |
| unseen seq below highest, DUP=1, inside window | legit | forward (original not observed) | `retransmit_original_unobserved` |
| unseen seq below highest, DUP=0 | replay | drop | `replay_late_sequence_nodup` |
| packet id reused after completion, **fresh** valid seq | legit | forward (legacy rule would false-alarm) | `pid_reuse_after_completion_fresh_seq` |
| DUP=1 resend of an ACKed txn right after session resume, same content, before any new publish | **uncertain** | forward (`uncertain_action`) | `possible_lost_ack_retransmit` |
| fresh message reusing an in-flight packet id | uncertain | forward | `pid_in_flight_reuse` |
| otherwise valid + fresh | legit | forward | `fresh_sequence` |

* **HMAC alone is never trusted for freshness**: a bit-exact replay has a valid HMAC and is dropped by state.
* **Reconnect:** `clean_session=0` keeps transactions (DUP resends of unACKed publishes are forwarded);
  `clean_session=1` clears packet-id state (per MQTT) but **keeps seq state**, so replays after a clean reconnect are
  still caught by Stage B (test: `test_clean_session_clears_pid_state_but_not_seq_state`).
* **Uncertain** cases are logged, forwarded by default (fail-open for legitimate delivery), configurable to drop.
* **Dropping safely:** by default the proxy answers a dropped QoS1 with PUBACK and QoS2 with PUBREC (+ swallows the
  later PUBREL, answering PUBCOMP) so a client state machine is not stalled; `silent`/`disconnect` are available.
* Every decision is logged to JSONL: `detector`, `classification`, `reason`, `action`, both stages' raw signals.

## 5. Results (measured; nothing estimated)

**Data provenance.** Legit traffic = **real captured** MQTTset/mqtt-malaria PUBLISHes (re-signed by the existing
`prepare_dataset.py`, so HMAC/seq/ts are *synthetic overlays*). Replays = **synthetic** (`attacker_replay.py`).
The capture has no CONNECT, so live runs wrap each original connection as client `dev-<port>` (synthetic).
All live tests in `tests/` are **synthetic**. The dataset's recorded PUBACKs feed the offline scoring; in live runs the
broker generates real ACKs.

### 5.1 Offline, original dataset (`results/offline/`, same `score.py` code for all three rows)
| Detector | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|---|---|---|
| Packet-ID / DUP reuse (original) | 40 | 0 | 4000 | 40 | 1.000 | 0.500 | 0.667 | 0.990 |
| HMAC + freshness (original) | 80 | 770 | 3230 | 0 | 0.094 | 1.000 | 0.172 | 0.811 |
| **Layered** | 80 | 0 | 4000 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |

Original two rows equal `external_eval/results/metrics.csv` exactly.

### 5.2 Live over TCP, three outputs, real Mosquitto 2.0.18 (`results/comparison.md`)
| Metric | Output 1: No IDS | Output 2: Layered IDS | Output 3: Layered IDS + minimized |
|---|---|---|---|
| Broker | mosquitto | mosquitto | mosquitto |
| Path | client -> broker | client -> IDS -> broker | client -> IDS (minimize) -> broker |
| Legit PUBLISH sent | 4000 | 4000 | 4000 |
| Legit delivered to subscriber | 4000 | 4000 | 4000 |
| Legit delivery rate | 1.0 | 1.0 | 1.0 |
| Replays sent | 80 | 80 | 80 |
| Replays delivered (leaked) | 80 | 0 | 0 |
| Replay blocking rate (delivery) | 0.0 | 1.0 | 1.0 |
| PUBLISH packets the broker received | 4080 | 4000 | 4000 |
| TP / FP / TN / FN | n/a (no detector) | 80 / 0 / 4000 / 0 | 80 / 0 / 4000 / 0 |
| Precision | n/a | 1.0 | 1.0 |
| Recall | n/a | 1.0 | 1.0 |
| F1 | n/a | 1.0 | 1.0 |
| Accuracy | n/a | 1.0 | 1.0 |
| Delivered payload bytes | 1354558 | 1327980 | 979980 |
| Auth fields (sig/seq/ts) reach app | yes | yes | no |
| Run time (s) | 0.73 | 1.24 | 1.33 |


"Delivered" = received by a subscriber connected **directly to Mosquitto**; "broker received" = PUBLISH packets in
**Mosquitto's own debug log** (`results/output*/mosquitto.log`). Both agree with the IDS log (4,080 without IDS vs 4,000 with it). Output 2 vs Output 3 vs offline engine: **4,080/4,080 decisions identical**
(`results/equivalence.json`). Output 3 reduced delivered payload bytes by 26.2 % on this data (1,327,980 → 979,980).

### 5.3 Other measured checks (all live runs on Mosquitto; `results/extra_runs_summary.json`)
* **`--replay-mode new_conn`** (attacker reconnects as the victim): Outputs 2 and 3 → TP 80 / FP 0 / TN 4000 / FN 0,
  0 replays delivered, Mosquitto received 4,000 PUBLISH (`results/new_conn/`).
* **Second real window** (`--skip 0`, all-fresh, no retransmissions; built with the original scripts; `results/extra_windows/`):
  Output 1 leaks 80/80; Outputs 2/3 → 80/0/4000/0, 0 leaked. Offline there: Packet-ID recall 0.50; HMAC rule 1.00/1.00
  (no retransmissions to false-alarm on, confirming the 770 FPs come from retransmissions). Replays here are caught as
  `replay_stale_sequence`.
* **`seq_window` sensitivity** (offline; `results/offline/seq_window_sensitivity.json`): FP = 748 @16, 475 @64, 181 @128,
  1 @178, **0 @≥179**; recall 1.000 throughout. Real retransmissions lag up to **178** seqs behind the highest, so the
  default 256 is **chosen using this capture** — see limitation 3.
* **Tests: 52, all pass on Mosquitto** (`results/test_report_mosquitto.txt`: 31 engine + 16 socket + 5 external-CSV, fresh broker per
  socket test). The same suite also passes on the bundled mini broker (re-run with `MQTT_TEST_BROKER=mini`).
  Earlier-development note: three engine tests reused an already-accepted seq (test bug) and one broker test raced the
  subscriber; both were corrected.

Coverage map → requirement: legit QoS1/QoS2 + retransmits (`TestLegit`, `test_qos2_*`); exact / dup-evasion / stale replay
(`TestReplay`); invalid HMAC + unsigned (`TestInvalid`, `test_invalid_hmac_and_unsigned_never_reach_broker`); packet-id reuse
after completion (`test_pid_reuse_*`); reconnect/session (`TestSessions`, `test_persistent_session_*`,
`test_clean_session_*`); Output 2 vs 3 equivalence (`test_equivalence_*` + live signature compare); broker delivery vs IDS
drop (`TestOutput2Layered`, `broker.received` assertions).

## 6. Limitations / not done (exact)

0. **Cross-identity replay is NOT detected (found and measured while preparing the paper).** The HMAC covers `topic|data|seq|ts`, not the sender, and replay state is keyed by CONNECT client-id, so a message captured from `devA` and sent as `devB` is forwarded as fresh. Documented by `test_cross_identity_replay_is_NOT_detected` and benchmark scenario S13 (leaks in all three configurations). Fix (not implemented): bind client-id into the MAC input and/or per-device keys.

1. **Not executed on Windows 11** (see top). Linux only.
2. **MQTT 3.1/3.1.1 only.** MQTT 5 CONNECT is rejected (`mqtt5: reject`); `passthrough` forwards it **uninspected**. No TLS termination.
3. **Dataset-tuned parameter:** `seq_window=256` was picked after measuring max retransmit lag 178 on one capture
   (mqtt-malaria, ~200 in-flight). Other devices need their own value. Larger window ⇒ wider bypass for limitation 6.
4. **Perfect scores (1.000) are on an easy, non-adaptive attack set** (verbatim copies of previously accepted packets,
   one capture tool). They do not establish generalization or resistance to an adaptive attacker.
5. **State is in memory.** After an IDS restart seq history is gone, so a message captured earlier looks fresh once.
   No persistence implemented.
6. A DUP=1 copy of a message the IDS **never observed**, with seq inside the window, is accepted once
   (indistinguishable from a legitimate retransmission of an unobserved original). An in-flight replay with DUP=1 is
   likewise indistinguishable from a retransmission by design.
7. **Delay/withhold attacks** (capturing and later delivering a never-seen message) need the timestamp check
   (`ts_max_age_s`), which is **off by default** (the dataset timestamps are from 2020).
8. **Device reboot that restarts `seq` at 1** is blocked as replay. The existing signing format has no epoch/boot
   counter; not implemented.
9. `uncertain_action=forward` lets a lost-ACK-lookalike replay through once; set `drop` for strict mode (tested).
10. Default `drop_response=ack` tells the sender its publish succeeded even though it was dropped.
11. Output 3 changes what subscribers receive; they must accept `{client_id,message}`. Broker→subscriber PUBLISH is not altered.
12. Tested with **Mosquitto 2.0.18 only** (loopback, anonymous, no TLS/auth/ACLs, persistence off). Other brokers/versions and
    broker bridges/clusters are untested. `mini_broker.py` is just a fallback (no auth/retain/will).
13. Single asyncio process; the ~1.3 s per 4,080 publishes is a sandbox observation, not a benchmark.
14. Client identity is the unauthenticated CONNECT client-id.
15. Delivery attribution is per-(topic,message) count; masking (one FP + one FN on the same key) is excluded by the IDS-log cross-check (`ids_verdict_aligned_with_dataset: true`).

## 7. Change log (additive; no original file edited)

* **Added** `replay_ids/` (engine, proxy, codec, config, minimizer, consumer, client, mini broker, decision log),
  `configs/` (3), `eval/` (offline + live evaluators, consumer demo), `run_output{1,2,3}_*.py`, `run_output.py`, `run_all.py`,
  `replay_ids/mosquitto_runner.py` (starts a private Mosquitto, parses its log), `tests/` (52), `docs/ARCHITECTURE.md`, `results/` (new measurements), this README.
* **Reused unchanged:** `mqtt_io` (remaining-length, builders), `signing` (HMAC verify/sign), `score.py` (scoring),
  `prepare_dataset.py` / `attacker_replay.py` (second window), `detectors.py` (baselines in the offline table).
* **Behavioural changes vs the originals (by design):** keyed by client-id not `(ip,port)`; QoS2 + session handling;
  acks must be *relayed* to count as completion; orphan ACKs ignored; packet-id reuse is no longer an alert by itself;
  seq freshness uses a seen-set + window instead of strict monotonicity.
* **Broker change in this revision:** all live runs/tests now execute on Mosquitto (default `--broker mosquitto`);
  the earlier mini-broker results were replaced, not mixed in. Folded the optional real-broker test file into the main suite.
* **Original results preserved:** `external_eval/` sha256-identical to the supplied ZIP (verified; original `results/` reproduces).
* Test-suite fixes made during development: three test cases initially reused an already-accepted seq (test bug, not
  engine bug) and one real-broker test raced the subscriber's delivery; both corrected.


## 8. Research paper and performance benchmark (added)

* `paper/main.pdf` - 8-page IEEE two-column paper (source: `paper/main.tex`, `paper/references.bib`, `paper/figures/`, `paper/tables/`).
* `bench/` - benchmark driver (`run_bench`), scenario matrix (`scenarios`), detector micro-benchmark (`bench_engine`), `analyze.py`, `make_tables.py`.
* `docs/REPRODUCE.md` - exact commands (Windows 11 PowerShell + Linux) and result-to-source map.
* Proxy instrumentation (timing, byte counters, `--stats`) was added for measurement only; decisions are unchanged
  (4,080/4,080 identical to the pre-instrumentation run; all 52 tests pass).

## 9. External CSV dataset (integrated)

Supplied files: `replay_attack.csv` (-> `external_data/`), `prepare_external_replay_csv.py`, `run_external_csv_three_outputs.py` (project root; two
small documented edits, see `docs/REPRODUCE.md` §1b). Results: `results/csv_external/` (as supplied, DUP=0) and `results/csv_external_dup1/`
(our synthetic DUP=1 variant). Headline: Output 1 delivers 1153/1153 reconstructed replays; Outputs 2 and 3 deliver 0, Mosquitto receives exactly the
27,588 negatives (TP 1153, FP 0, FN 0), Output 2 = Output 3 decisions on all 28,741 packets. **Caveat:** all three detectors also score perfectly offline on the
DUP=0 data (no retransmissions, no DUP variety), so this dataset shows generalization and zero false positives, *not* an advantage of layering; only the
DUP=1 variant separates the original Packet-ID rule (0/1153) from the others. It is a reconstruction, not a capture; see the manifest for synthesized fields.
