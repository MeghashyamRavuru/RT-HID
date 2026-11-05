#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 -m venv "$ROOT_DIR/.venv"
"$ROOT_DIR/.venv/bin/python" -m pip install --upgrade pip
"$ROOT_DIR/.venv/bin/pip" install -e "$ROOT_DIR"
printf 'Installed RT-NID-ML environment at %s/.venv\n' "$ROOT_DIR"
printf 'Copy config/host_ids.json to /etc/rt-nid-ml and edit host_id before enabling systemd.\n'
