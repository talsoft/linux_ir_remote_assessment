"""Configuration dataclasses."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class OutputPaths:
    evidence_dir: Path
    raw_dir: Path
    reports_dir: Path
    commands_log: Path
    evidence_index: Path


@dataclass(frozen=True)
class AssessmentConfig:
    host: str
    port: int
    user: str
    key_file: Path | None
    key_passphrase: str | None
    password: str | None
    fallback_password: bool
    sudo: bool
    sudo_password: str | None
    mode: str
    output_root: Path
    paths: OutputPaths
    non_interactive: bool
    abuse_investigation: bool
    assessment_id: str
