"""Import JSONL/JSON/CSV security events through the normal ingestion path."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database.connection import create_database  # noqa: E402
from src.services.soc_service import SocService  # noqa: E402
from src.utils.config import resolve_database_url  # noqa: E402
from src.utils.helpers import chunked  # noqa: E402


def load_records(path: Path, fmt: str) -> list[dict[str, Any]]:
    if fmt == "jsonl":
        records = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    records.append(json.loads(line))
        return records
    if fmt == "json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and "events" in payload:
            return list(payload["events"])
        if isinstance(payload, list):
            return payload
        raise SystemExit("JSON input must be a list or an object with an 'events' array")
    if fmt == "csv":
        with path.open("r", encoding="utf-8", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    raise SystemExit(f"Unsupported format: {fmt}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import labelled events into the SOC database.")
    parser.add_argument("--input", required=True, help="Path to JSONL, JSON, or CSV events.")
    parser.add_argument("--format", choices=["jsonl", "json", "csv"], default=None)
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--source", default="imported_dataset")
    parser.add_argument("--dataset-label", default="synthetic_demo_data")
    parser.add_argument("--limit", type=int, default=0, help="Maximum events to import (0 = all).")
    parser.add_argument("--investigate", action="store_true", help="Run the full agent on created incidents.")
    args = parser.parse_args()

    path = Path(args.input)
    fmt = args.format or path.suffix.lstrip(".").lower()
    if fmt not in {"jsonl", "json", "csv"}:
        raise SystemExit("Could not infer --format; pass jsonl, json, or csv")
    records = load_records(path, fmt)
    if args.limit:
        records = records[: args.limit]
    if not records:
        raise SystemExit("No records found")
    if any("source_ip" not in record and "line" not in record for record in records[:5]):
        print("WARNING: some records have no source_ip/line; they will still be normalized and stored.")

    for record in records:
        record.setdefault("dataset_label", args.dataset_label)
        if record.get("dataset_label") in {None, ""}:
            record["dataset_label"] = args.dataset_label

    url = resolve_database_url(args.database_url)
    engine, session_factory = create_database(url)
    service = SocService(session_factory)
    submitted = ingested = duplicates = alerts = 0
    incident_ids: set[str] = set()
    investigations = []
    try:
        for group in chunked(records, 500):
            result = service.ingest_batch(
                list(group), actor="dataset_importer", actor_role="system",
                source=args.source, enable_ml=None, auto_investigate=False,
            )
            submitted += result["submitted"]
            ingested += result["ingested"]
            duplicates += result["duplicates"]
            alerts += result["alerts_created"]
            incident_ids.update(result["incidents"])
        if args.investigate:
            for incident_id in sorted(incident_ids):
                investigations.append(service.investigate(
                    incident_id, actor="dataset_importer", actor_role="system"
                ))
        metrics = service.metrics()
    finally:
        engine.dispose()

    summary = {
        "source": str(path),
        "format": fmt,
        "data_label": args.dataset_label,
        "submitted": submitted,
        "ingested": ingested,
        "duplicates": duplicates,
        "alerts_created": alerts,
        "incidents": sorted(incident_ids),
        "investigations": len(investigations),
        "database_totals": metrics["totals"],
        "audit_chain_valid": metrics["audit"]["chain_valid"],
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
