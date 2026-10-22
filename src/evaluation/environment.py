"""Runtime environment capture for reproducible evaluation reports."""
from __future__ import annotations

import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy
import pandas
import sklearn

from src.utils.config import PROJECT_ROOT


def _git_commit() -> str | None:
    """Return the current commit without invoking a shell.

    Reading ``.git`` directly keeps evaluation side-effect free and works
    offline. Detached HEADs and packed refs are handled explicitly.
    """
    git_dir = PROJECT_ROOT / ".git"
    if not git_dir.exists():
        return None
    head = git_dir / "HEAD"
    if not head.exists():
        return None
    value = head.read_text(encoding="utf-8").strip()
    if not value.startswith("ref: "):
        return value[:12] or None
    ref = value[5:].strip()
    ref_path = git_dir / ref
    if ref_path.exists():
        return ref_path.read_text(encoding="utf-8").strip()[:12]
    packed = git_dir / "packed-refs"
    if packed.exists():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("#", "^")):
                sha, _, name = line.partition(" ")
                if name.strip() == ref:
                    return sha[:12]
    return None


def environment_info() -> dict[str, Any]:
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "not_reported",
        "cpu_count": os.cpu_count(),
        "project_root": str(PROJECT_ROOT),
        "git_commit": _git_commit(),
        "packages": {
            "numpy": numpy.__version__,
            "pandas": pandas.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
    }


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
