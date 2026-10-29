# Running the two replay detectors on the real capture

Self-contained. Needs Python 3 and scapy (`pip install scapy`). Nothing here
imports the rest of the project. Run all commands from inside `external_eval`.

The real capture is used as the legit background traffic. Signing is added on
top (so the HMAC detector has something to verify). An attacker step then
performs the two replays on the real packets. Both detectors are scored and
the confusion matrices, precision, recall and accuracy are printed.

## Step 1 - build the signed legit base from the real capture
    python prepare_dataset.py --pcap /path/to/external_mqttset_malaria.pcap --skip 0 --count 4000

  --count  how many real publishes to use as legit traffic
  --skip   how many publishes to skip first (choose the window)

The early part of this capture is all fresh traffic; real retransmissions
begin later. For the richer experiment that includes real retransmissions,
skip into that region:

    python prepare_dataset.py --pcap /path/to/external_mqttset_malaria.pcap --skip 48000 --count 4000

## Step 2 - the attacker performs the two replays
    python attacker_replay.py --type1 40 --type2 40

  --type1  number of exact replays        (reused packet-id, DUP=0)
  --type2  number of dup-evasion replays  (reused packet-id, DUP=1)

It prints each replayed packet and then the dataset composition (how many
legit, how many replay, split into type1 and type2).

## Step 3 - score both detectors
    python score.py

It prints the packets used, then for each detector a confusion matrix with
TP/TN/FP/FN, precision, recall, F1 and accuracy, plus a per-type breakdown.
Results are also written to results/metrics.csv and results/confusion_matrices.json.

## Changing the shared key
The signing key defaults to a lab value. Override it (used by both the signer
and the detector) with an environment variable before running:

    setx MQTT_HMAC_SECRET "your-secret"     (Windows, new terminal after)
    export MQTT_HMAC_SECRET="your-secret"   (Linux/macOS)
