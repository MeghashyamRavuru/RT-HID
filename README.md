# RT-NID-ML

A lightweight flow-based network intrusion detection pipeline. It trains a
multiclass model, replays PCAP files, sniffs live TCP traffic with Scapy, and
exposes a small polling dashboard for alerts.

## What it detects

- Normal traffic
- Port scanning
- Brute-force-like connection bursts
- Denial-of-service-like floods
- C2-like periodic traffic

## Quick start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Train the multiclass starter model:

```bash
python -m rt_nid_ml.train --output models/nid_model.joblib
```

Run the command from the repository with `PYTHONPATH=src` on Windows PowerShell
(`$env:PYTHONPATH="src"`) or install the package in editable mode.

3. Replay a PCAP (no capture privileges required):

```bash
python -m rt_nid_ml.detector --pcap capture.pcap --model models/nid_model.joblib
```

4. Run live detection (administrator/root privileges and Npcap/libpcap may be
required):

```bash
python -m rt_nid_ml.detector --interface Ethernet --model models/nid_model.joblib
```

5. Start the dashboard in another terminal:

```bash
python -m rt_nid_ml.dashboard --port 5000
```

Open `http://127.0.0.1:5000`. Alerts are emitted as JSON lines and are also
available from `/api/summary`. The trainer currently creates reproducible
synthetic data so the full pipeline can be demonstrated without a dataset;
replace `build_synthetic_training_data` with CICFlowMeter/CICIDS2017 rows for
production training.