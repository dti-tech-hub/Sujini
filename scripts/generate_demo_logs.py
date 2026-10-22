"""Write labelled synthetic web logs and JSON alert fixtures for demonstrations."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.demo_scenarios import (  # noqa: E402
    benign_traffic_scenario, brute_force_compromise_scenario,
)
from src.utils.config import DATA_DIR  # noqa: E402


def _log_line(event: dict) -> str:
    timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
    user = event.get("username") or "-"
    path = event.get("destination") or event.get("endpoint") or "/"
    method = event.get("method") or "GET"
    status = event.get("status_code") or 200
    size = event.get("size", 512)
    ua = event.get("user_agent") or "-"
    return (
        f'{event.get("source_ip", "-")} - {user} '
        f'[{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] '
        f'"{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate labelled synthetic demo logs.")
    parser.add_argument("--output-dir", default=str(DATA_DIR))
    args = parser.parse_args()
    output = Path(args.output_dir)
    logs_dir = output / "sample_logs"
    alerts_dir = output / "sample_alerts"
    logs_dir.mkdir(parents=True, exist_ok=True)
    alerts_dir.mkdir(parents=True, exist_ok=True)

    attack = brute_force_compromise_scenario()
    benign = benign_traffic_scenario()

    attack_log = logs_dir / "demo_web_access.log"
    attack_log.write_text(
        "# data_label: synthetic_demo_data\n"
        "# scenario: brute_force_account_compromise\n"
        + "\n".join(_log_line(event) for event in attack["events"])
        + "\n",
        encoding="utf-8",
    )
    benign_log = logs_dir / "benign_web_access.log"
    benign_log.write_text(
        "# data_label: synthetic_demo_data\n"
        "# scenario: benign_browsing\n"
        + "\n".join(_log_line(event) for event in benign["events"])
        + "\n",
        encoding="utf-8",
    )
    alerts_path = alerts_dir / "demo_events.json"
    alerts_path.write_text(
        json.dumps(
            {
                "data_label": "synthetic_demo_data",
                "scenario": attack["name"],
                "ground_truth": attack["ground_truth"],
                "events": attack["events"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(json.dumps({
        "data_label": "synthetic_demo_data",
        "attack_log": str(attack_log),
        "attack_events": len(attack["events"]),
        "benign_log": str(benign_log),
        "benign_events": len(benign["events"]),
        "alerts_json": str(alerts_path),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
