# RT-NID-ML

Minimal real-time network intrusion detector for SSH traffic using packet-level
features and an ML classifier.

## What it detects

- High-confidence suspicious SSH sources associated with brute-force behavior
  (rapid connection attempts and resets)
- Benign SSH packet patterns (normal interactive sessions)

## Quick start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Train a starter model:

```bash
python /home/runner/work/RT-NID-ML/RT-NID-ML/src/rt_nid_ml/train.py --output /home/runner/work/RT-NID-ML/RT-NID-ML/models/ssh_intrusion_model.joblib
```

3. Run real-time detector (requires privileges for packet capture):

```bash
sudo python /home/runner/work/RT-NID-ML/RT-NID-ML/src/rt_nid_ml/detector.py --interface eth0 --model /home/runner/work/RT-NID-ML/RT-NID-ML/models/ssh_intrusion_model.joblib
```

Alerts are emitted as JSON lines with source IP, score, and extracted feature
values.