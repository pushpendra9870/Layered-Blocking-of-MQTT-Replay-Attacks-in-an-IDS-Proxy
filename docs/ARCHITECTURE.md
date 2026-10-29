# Architecture and packet flow

## 1. Deployment (the three outputs)

```
Output 1  NO IDS
  [client] ───────────────────────────────────────────────▶ [broker]
   (signed payloads sent, nothing is checked)

Output 2  LAYERED IDS
  [client] ──▶ [ IDS proxy :1884 ] ──forward legit──────▶ [broker :1883]
                │  Stage A  packet-id / DUP / ack state
                │  Stage B  HMAC + sequence freshness      ◀── PUBACK/PUBREC/PUBCOMP,
                │  Correlator ──▶ forward | drop               SUBACK, PUBLISH relayed back
                └─ decisions.jsonl (detector, class, reason, action)

Output 3  LAYERED IDS + MINIMIZED APPLICATION DATA
  same as Output 2, but the forwarded PUBLISH payload becomes
        {"client_id": "...", "message": <device data>}      (no sig / seq / ts)
  and  app_feed.jsonl  carries {client_id, message, keep_alive}
  [consumer_min] ◀── broker ◀── minimized PUBLISH
```

## 2. Packet flow through the proxy (Output 2 / 3)

```mermaid
sequenceDiagram
    participant C as Client
    participant P as IDS proxy
    participant B as Broker
    C->>P: CONNECT(client_id, clean, keep_alive)
    P->>P: engine.on_connect (clean=1 clears packet-id state, NOT seq state)
    P->>B: CONNECT (unchanged)
    B-->>P: CONNACK
    P-->>C: CONNACK (relayed)
    C->>P: PUBLISH QoS1 pid=7 {data,seq,ts,sig}
    P->>P: Stage A + Stage B + Correlator
    alt legit / retransmit (forward)
        P->>B: PUBLISH (Output 3: payload rewritten to {client_id,message})
        B-->>P: PUBACK 7
        P->>P: txn 7 -> completed
        P-->>C: PUBACK 7
    else confirmed replay (drop)
        P->>P: log {detector, class, reason, action=drop}
        P-->>C: synthetic PUBACK 7 (drop_response=ack)  -- nothing sent to broker
    end
    Note over C,B: PINGREQ/PINGRESP, SUBSCRIBE/SUBACK, broker->client PUBLISH pass through untouched
```

## 3. Decision pipeline

```mermaid
flowchart TD
    A[PUBLISH from client] --> S{Signed envelope<br/>parses?}
    S -- no --> M[INVALID missing_signature<br/>drop by default]
    S -- yes --> H{HMAC valid?}
    H -- no --> I[INVALID invalid_hmac<br/>drop by default]
    H -- yes --> F{Sequence status<br/>Stage B}
    F -- below window --> R1[REPLAY stale_sequence DROP]
    F -- seen before --> T{Stage A: packet-id<br/>transaction state}
    T -- same content & in flight & DUP=1 --> L1[LEGIT retransmit_inflight FORWARD]
    T -- in flight & DUP=0 --> R2[REPLAY duplicate_inflight_nodup DROP]
    T -- completed --> U{reconnect, DUP=1, same content,<br/>within resend window, before new publish?}
    U -- yes --> Q[UNCERTAIN possible_lost_ack_retransmit<br/>FORWARD by default]
    U -- no --> R3[REPLAY completed_transaction DROP]
    T -- no txn / content differs --> R4[REPLAY seq_already_accepted / content_mismatch DROP]
    F -- fresh or late-unseen --> G{late-unseen & DUP=0?}
    G -- yes --> R5[REPLAY late_sequence_nodup DROP]
    G -- no --> P{pid state}
    P -- in flight --> Q2[UNCERTAIN pid_in_flight_reuse FORWARD]
    P -- completed --> L2[LEGIT pid_reuse_after_completion_fresh_seq]
    P -- unused, DUP=1 --> L3[LEGIT retransmit_original_unobserved]
    P -- unused, DUP=0 --> L4[LEGIT fresh_sequence]
```

## 4. Why both layers are needed (measured on the real capture, see README)

| Failure of one layer | Example | Fixed by |
|---|---|---|
| Packet-ID rule misses DUP-evasion replay (recall 0.50) | replay with DUP=1 on an ACKed id | seen-sequence check (Stage B) |
| Packet-ID rule flags legitimate id reuse after ACK | id 7 reused with a *new* signed seq | fresh seq overrides (Stage B) |
| HMAC freshness flags legitimate retransmissions (770 FPs) | DUP=1 resend, original seq | open-transaction state + seen-set (Stage A) |
| HMAC alone accepts a bit-exact replay | valid signature, old message | seq state; HMAC is only authenticity |
| Clean-session reconnect erases packet-id state | replay after reconnect | seq state survives reconnects |

## 5. Code map

| File | Role |
|---|---|
| `external_eval/*` | ORIGINAL code, dataset, results (unmodified; reused: `mqtt_io`, `signing`, `score`, `detectors` as baselines) |
| `replay_ids/engine.py` | Stage A, Stage B, correlator (shared by Outputs 2 and 3) |
| `replay_ids/proxy.py` | asyncio TCP proxy, drop/forward/ack-synthesis, minimization hook |
| `replay_ids/codec.py` | stream framer, CONNECT/PUBLISH/ack parse + build |
| `replay_ids/minimizer.py` | Output 3 payload + app feed |
| `replay_ids/consumer_min.py` | Output 3 demo consumer |
| `replay_ids/mini_broker.py` | zero-install test broker (logs every PUBLISH it receives) |
| `eval/offline_eval.py`, `eval/live_eval.py` | scoring on the existing dataset (offline / over real TCP) |
| `run_output{1,2,3}_*.py`, `run_all.py` | the three entry points + everything-at-once |
