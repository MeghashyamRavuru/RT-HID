# Project direction

The project began as an ML based network IDS for SSH traffic. It then expanded into a network flow research pipeline using CICIDS2017 data, PCAP/live capture, and flow models. The current goal is different: **a standalone host intrusion detector installed on each machine**. Each Ubuntu/Linux or Windows host detects and displays its own alerts locally. There is no central IDS service.

The repository was cleaned for that goal on 5 November 2026. The old network capture, training, inference, dashboards, datasets, model, and their tests were removed. Their committed source remains in Git history. The host agent is now the application in `src/rt_nid_ml/host/`.

Current detection is rule based. Linux uses auth logs plus local process, listener, file, and system polling. Windows uses Security log events plus the same local polling signals. Both feed normalized events into the host rule engine, SQLite incident store, and local dashboard. Adding another attack means adding an appropriate host signal and a rule with evidence; the system must not claim to detect attacks for which it has no signal.

The immediate product priorities are reliable local collection on both operating systems, clear collector health, useful low-noise rules, and straightforward installation. The name `RT-NID-ML` is historical; it does not describe the current host detector or imply that ML is active.
