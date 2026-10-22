"""Initialise the database and seed one account per role.

No default password is embedded in source. Passwords come from environment
variables or are randomly generated and written to a local, git-ignored file.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.database import repository  # noqa: E402
from src.database.connection import create_database  # noqa: E402
from src.security.audit import AuditService  # noqa: E402
from src.security.passwords import generate_password, hash_password  # noqa: E402
from src.utils.config import DATA_DIR, resolve_database_url  # noqa: E402

ROLES = ("admin", "analyst", "viewer")


def _reset_sqlite(url: str) -> None:
    if not url.startswith("sqlite:///"):
        raise SystemExit("--reset is only supported for SQLite databases")
    raw = url[len("sqlite:///"):]
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    if path.name in {"soc.db", "demo.db"} or path.suffix == ".db":
        for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
            if candidate.exists():
                candidate.unlink()
        print(f"Removed existing SQLite database: {path}")
    else:
        raise SystemExit(f"Refusing to remove unexpected path: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed SOC users and initialise tables.")
    parser.add_argument("--database-url", default=None, help="SQLAlchemy URL; defaults to config/env.")
    parser.add_argument("--reset", action="store_true", help="Delete the SQLite file before seeding.")
    parser.add_argument(
        "--credentials-file", default=str(DATA_DIR / "credentials.json"),
        help="Where generated passwords are written (local only).",
    )
    args = parser.parse_args()

    url = resolve_database_url(args.database_url)
    if args.reset:
        _reset_sqlite(url)
    engine, session_factory = create_database(url)
    session = session_factory()
    generated: dict[str, str] = {}
    created: list[str] = []
    existing: list[str] = []
    try:
        for role in ROLES:
            username = f"{role}"
            found = repository.get_user_by_username(session, username)
            if found:
                existing.append(username)
                continue
            env_name = f"SOC_{role.upper()}_PASSWORD"
            password = os.getenv(env_name, "").strip()
            if not password:
                password = generate_password(24)
                generated[username] = password
            repository.create_user(session, username, hash_password(password), role)
            created.append(username)
        AuditService(session).record(
            actor="bootstrap", actor_role="system", action="USERS_SEEDED",
            entity_type="user", outcome="SUCCESS",
            details={"created": created, "existing": existing, "database": url.split(":", 1)[0]},
        )
        session.commit()
    finally:
        session.close()
        engine.dispose()

    payload = {
        "database": url,
        "created_users": created,
        "existing_users": existing,
        "generated_credentials": generated,
        "note": (
            "Passwords are shown once. Store them outside version control. "
            "Set SOC_ADMIN_PASSWORD/SOC_ANALYST_PASSWORD/SOC_VIEWER_PASSWORD to choose your own."
        ),
    }
    if generated:
        target = Path(args.credentials_file)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            target.chmod(0o600)
        except OSError:
            pass
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
