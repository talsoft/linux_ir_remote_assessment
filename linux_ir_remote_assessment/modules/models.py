"""Shared data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CommandResult:
    name: str
    command: str
    exit_status: int
    stdout: str
    stderr: str
    evidence_path: str | None = None
    privileged: bool = False


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    category: str = "general"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionResult:
    commands: list[CommandResult] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AbuseInvestigationResult:
    findings: list[Finding] = field(default_factory=list)
    root_cause: list[dict[str, Any]] = field(default_factory=list)
