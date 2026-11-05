# RT-NID-ML

A lightweight flow-based network intrusion detection pipeline. It trains a multiclass model, replays PCAP files, sniffs live TCP traffic with Scapy, and exposes a small polling dashboard for alerts.

## CICIDS2017 training

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Place the CICIDS2017 CSV files in `datasets/` (or provide another directory).

3. Train and evaluate:

```bash
python -m rt_nid_ml.train --dataset-dir datasets --output models/cicids_flow_model.joblib
```

The trainer normalizes CICIDS2017 labels, samples up to 15,000 rows per mapped class, and handles missing/non-finite values. Evaluation uses two protocols: a duplicate-aware stratified row split and an unseen-capture-file split where the dataset permits it. Flow fingerprints found in both partitions are excluded from test metrics. Reports include overall metrics, per-class support and capture-file counts, and a macro-F1 restricted to classes with at least 50 independent test samples.

The final test is kept separate from a calibration partition. A sigmoid-calibrated Random Forest selects operating thresholds from benign calibration flows for target FPRs of 1%, 0.5%, and 0.1%. Each report includes the actual FPR, precision, recall, and TP/FP/FN/TN counts; target FPRs are operating objectives, not guarantees. The artifact records calibration metadata, thresholds, scikit-learn version, feature schema version, and is reloaded and smoke-tested after saving.

Heartbleed and Infiltration are always marked statistically insufficient because they occur in too few records and capture files for reliable unseen-file claims. Capture-file results should therefore be treated as the more conservative generalization estimate; the random row split is useful for comparison but can still share capture conditions between train and test.

**Compatibility warning:** The saved CICIDS2017 artifact uses CICFlowMeter flow-level features. The current live detector still extracts a different 10-feature packet-window schema. Do not pass `cicids_flow_model.joblib` to the current detector until its feature extraction is aligned in a separate integration step.

## Phase 2 flow extraction

`src/rt_nid_ml/flow_extractor.py` contains an independent bidirectional flow
engine. It accepts synthetic or capture-adapter events containing timestamp,
IPv4 endpoints and ports, protocol, packet size, optional payload size, and
TCP flags. Canonical five-tuples merge forward and reverse packets while
keeping direction-specific counters. Active and inactive timeouts emit
completed flow records, and `max_flows` bounds memory with explicit capacity
eviction records.

The `LIVE_FLOW_FEATURE_COLUMNS` schema is a new live numeric schema based on
these packet events. It is not equivalent to the 21 CICFlowMeter training
features and is not connected to model inference yet. IPv4 TCP and UDP are
supported; IPv6 and other protocols are rejected explicitly until a later
extension.

## Phase 3A Scapy capture

`src/rt_nid_ml/scapy_adapter.py` translates Scapy IPv4 TCP/UDP packets into
the Phase 2 `PacketEvent` contract and forwards them to the existing flow
extractor. `ScapyCapture` accepts a configurable interface and BPF filter,
supports blocking `run()` and non-blocking `start_background()` capture, and
returns structured capture statistics. It handles malformed packets,
unsupported protocols, capture errors, and shutdown flushing without invoking
the ML model or dashboard.

Live capture may require Npcap/libpcap and administrator privileges. The
adapter does not make the Phase 2 live features equivalent to CICFlowMeter,
and it is not yet connected to model inference.

## Phase 3B live-flow dataset collection

`src/rt_nid_ml/dataset_collector.py` consumes completed `FlowRecord` objects
and writes append-only `session_<id>.csv` files with JSON sidecars. Each row
contains all 15 live features, canonical flow endpoints and protocol, start
and end timestamps, lifecycle reason, session ID, sensor ID, experiment ID,
experiment window, target IP, ground-truth label, label source, confidence,
clock uncertainty, and labeling rationale. Packet payload contents are never
stored.

Labels are assigned only when explicit experiment metadata overlaps the flow
time window and one of the flow endpoints matches the experiment target. The
supported labels are `normal`, `port_scan`, `brute_force`, `dos`, and
`unknown`; unmatched or conflicting records remain `unknown`. Manual review
can create a derived corrected CSV with original label provenance:

```bash
python -m rt_nid_ml.dataset_collector validate path/to/session.csv
```

Validation reports schema mismatches, missing or invalid values, duplicate
flows, incomplete lifecycle records, unknown labels, and label/session/
protocol distributions. It does not silently delete questionable rows.

Collection requires an explicit experiment metadata JSON file for trusted
labels and can be started with the Phase 3A capture adapter. This phase does
not train or invoke an ML model.

## Phase 4 live-compatible training

`src/rt_nid_ml/live_train.py` is a separate trainer for collected
`live-flow-dataset-v1` sessions. It validates CSV sidecars and the exact 15
`LIVE_FLOW_FEATURE_COLUMNS`, excludes unknown/invalid/duplicate rows with
reported reasons, maps verified attack labels to either binary `suspicious`
or distinct `port_scan`/`brute_force`/`dos` classes, and refuses runs without
enough independent session support.

Training uses disjoint session-aware train, calibration, threshold, and final
test partitions. It compares Random Forest, Extra Trees, and histogram
gradient boosting, applies sigmoid calibration, and selects 1%, 0.5%, and
0.1% FPR operating points only from the threshold partition. Unsupported FPR
targets are marked rather than claimed.

Example:

```bash
python -m rt_nid_ml.live_train --dataset-dir collected --output models/live_flow_model.joblib --approach binary
```

The resulting artifact is tagged `live_flow_model` and is intentionally not
compatible with the CICIDS2017 artifact or the existing detector yet.

## Phase 5 live inference

`src/rt_nid_ml/live_detector.py` loads only validated `live_flow_model`
artifacts and connects completed Phase 2 flows to calibrated inference through
the Phase 3A capture adapter. It validates the exact feature order, schema and
artifact versions, estimator/calibrator class ordering, calibration metadata,
and every threshold configuration before processing traffic.

Binary artifacts produce `benign` or `suspicious`; multiclass artifacts
produce `port_scan`, `brute_force`, or `dos` when the selected threshold is
supported. Invalid features, unsupported thresholds, incomplete flows under
the default policy, invalid probabilities, and uncertain decisions return
structured `unknown` results. Completed flow IDs are deduplicated and all
results retain flow lifecycle metadata.

Example, without dashboard or remote alert integration:

```bash
python -m rt_nid_ml.live_detector --interface Ethernet --model models/live_flow_model.joblib
```

This validates the software pipeline only; it does not establish real-world
detection effectiveness.

## Phase 6 alert management

`src/rt_nid_ml/alert_manager.py` consumes immutable `DetectionResult` values
after inference. It preserves raw detection evidence and applies configurable
port-scan, brute-force-like, and DoS-like temporal correlation rules without
changing model probabilities. Allowlists, source rate limits, duplicate
suppression, cooldowns, sensitive-service severity adjustments, bounded event
retention, and incident retention are configurable through
`AlertManagerConfig`.

Security alerts include stable incident references, source/target details,
related event IDs, raw detection evidence, severity, confidence, suppression
state, and correlation rationale. Incidents support `new`, `updated`,
`acknowledged`, and `resolved` states. Suppressed and unknown detections are
retained as structured evidence; they are not silently discarded. This phase
does not connect alerts to the dashboard or remote ingestion backend.

## Existing detector workflow

The existing detector remains unchanged by this training update. Use a model already compatible with its current feature schema for PCAP replay/live capture:

```bash
python -m rt_nid_ml.detector --pcap capture.pcap --model models/nid_model.joblib
python -m rt_nid_ml.detector --interface Ethernet --model models/nid_model.joblib
```
