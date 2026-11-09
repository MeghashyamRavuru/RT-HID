from __future__ import annotations

import argparse
import logging
import platform
import threading
import json
from pathlib import Path

from .agent import HostAgent
from .api import create_app
from .config import HostConfig
from .maintenance import validate_backup, restore_backup


def build_config(args: argparse.Namespace) -> HostConfig:
    if args.config:
        config = HostConfig.from_json(Path(args.config))
    else:
        config = HostConfig(host_id=args.host_id or platform.node())
    config.validate()
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone local RT-HID host IDS")
    parser.add_argument("--config", help="JSON host configuration path")
    parser.add_argument("--host-id")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("monitor")
    dashboard = sub.add_parser("dashboard")
    dashboard.add_argument("--host", dest="dashboard_host")
    dashboard.add_argument("--port", type=int, dest="dashboard_port")
    sub.add_parser("alerts")
    sub.add_parser("incidents")
    sub.add_parser('backup')
    validate = sub.add_parser('validate-backup')
    validate.add_argument('path')
    restore = sub.add_parser('restore-backup')
    restore.add_argument('source')
    restore.add_argument('destination')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = build_config(args)
    if args.command == 'validate-backup':
        print(json.dumps(validate_backup(Path(args.path))))
        return
    if args.command == 'restore-backup':
        if Path(args.destination).resolve() == config.database_path.resolve():
            parser.error('restore to a new database path, validate it, then switch configuration while RT-HID is stopped')
        print(json.dumps(restore_backup(Path(args.source),Path(args.destination))))
        return
    agent = HostAgent(config)
    monitor: threading.Thread | None = None
    try:
        if args.command == "status":
            print(agent.status())
        elif args.command == "alerts":
            print(agent.database.list_alerts())
        elif args.command == "incidents":
            print(agent.database.list_incidents())
        elif args.command == 'backup':
            print(json.dumps(agent.maintenance.backup()))
        elif args.command == "monitor":
            agent.run_forever()
        elif args.command == "dashboard":
            host = args.dashboard_host or config.dashboard_host
            if host not in {"127.0.0.1", "::1", "localhost"}:
                parser.error("dashboard must bind to loopback; use a local browser or an HTTPS reverse proxy")
            monitor = threading.Thread(target=agent.run_forever, kwargs={"install_signals": False}, daemon=True)
            monitor.start()
            app = create_app(agent)
            app.run(host=host, port=args.dashboard_port or config.dashboard_port, debug=False)
    finally:
        agent.stop_event.set()
        if monitor is not None:
            monitor.join(timeout=5)
        agent.stop()


if __name__ == "__main__":
    main()
