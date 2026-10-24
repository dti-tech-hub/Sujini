"""Import raw web-server logs or JSONL security events through the real API.

Supported inputs:
  * Apache/Nginx combined access logs (``--format clf``)
  * one JSON object per line (``--format jsonl``)

The importer only reads text and POSTs it to ``/api/events/batch``. Log content
is never executed, interpreted as a command, or used to select a response.

Example:
    .\\.venv\\Scripts\\python.exe scripts\\import_logs.py --file access.log --format clf ^
        --username admin --dataset-label synthetic_demo_data
"""
from __future__ import annotations

import argparse
import csv
import getpass
import json
import sys
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.detection.normalization import parse_web_log_line  # noqa: E402


def load_records(path: Path, fmt: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if fmt == "jsonl":
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
    if fmt == "csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            records.extend(dict(row) for row in csv.DictReader(handle))
        return records
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(parse_web_log_line(line))
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Import web logs/events into the SOC API.")
    parser.add_argument("--file", required=True, help="Input log or JSONL file.")
    parser.add_argument("--format", choices=["clf", "jsonl", "csv"], default="clf")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", default=None, help="Prompted interactively when omitted.")
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument(
        "--dataset-label",
        default=None,
        help="Provenance label, e.g. synthetic_demo_data for generated demo logs.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Parse and count without sending.")
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")
    records = load_records(path, args.format)
    if args.dataset_label:
        for record in records:
            record.setdefault("dataset_label", args.dataset_label)
    print(f"Parsed {len(records)} record(s) from {path} ({args.format}).")
    if args.dry_run:
        return 0
    if not records:
        return 0

    password = args.password or getpass.getpass("API password: ")
    base = args.api_url.rstrip("/")
    try:
        login = httpx.post(
            f"{base}/auth/login",
            json={"username": args.username, "password": password},
            timeout=30,
        )
    except httpx.RequestError as exc:
        raise SystemExit(f"Cannot reach the API at {base}: {exc}") from exc
    if login.status_code != 200:
        raise SystemExit(f"Login failed ({login.status_code}): {login.text[:500]}")
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    totals = {"submitted": 0, "ingested": 0, "duplicates": 0, "alerts_created": 0, "incidents": 0}
    for start in range(0, len(records), args.batch_size):
        chunk = records[start:start + args.batch_size]
        try:
            response = httpx.post(
                f"{base}/api/events/batch",
                json={"events": chunk},
                headers=headers,
                timeout=120,
            )
        except httpx.RequestError as exc:
            raise SystemExit(f"Batch upload failed at offset {start}: {exc}") from exc
        if response.status_code >= 400:
            raise SystemExit(f"Batch upload failed ({response.status_code}): {response.text[:1000]}")
        payload = response.json()
        for key in ("submitted", "ingested", "duplicates", "alerts_created"):
            totals[key] += int(payload.get(key, 0))
        totals["incidents"] += len(payload.get("incidents", []))
        print(
            f"  batch {start // args.batch_size + 1}: "
            f"{payload.get('ingested', 0)} ingested, {payload.get('alerts_created', 0)} alerts"
        )

    print(json.dumps(totals, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
