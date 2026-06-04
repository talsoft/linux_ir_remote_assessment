"""Utility helpers."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.config import OutputPaths


SECRET_PATTERNS = [
    re.compile(r"(password\s*[:=]\s*)\S+", re.IGNORECASE),
    re.compile(r"(passphrase\s*[:=]\s*)\S+", re.IGNORECASE),
]


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_output_tree(output_root: Path) -> OutputPaths:
    evidence_dir = output_root / "evidence"
    raw_dir = evidence_dir / "raw"
    reports_dir = output_root / "reports"
    for path in (output_root, evidence_dir, raw_dir, reports_dir):
        path.mkdir(parents=True, exist_ok=True)
    return OutputPaths(
        evidence_dir=evidence_dir,
        raw_dir=raw_dir,
        reports_dir=reports_dir,
        commands_log=output_root / "commands.log",
        evidence_index=output_root / "evidence_index.json",
    )


def sanitize_text(text: str) -> str:
    sanitized = text
    for pattern in SECRET_PATTERNS:
        sanitized = pattern.sub(r"\1<redacted>", sanitized)
    return sanitized


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned.strip("_") or "item"


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="replace")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def severity_rank(severity: str) -> int:
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
    }.get(severity.lower(), 0)
