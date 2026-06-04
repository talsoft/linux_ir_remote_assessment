"""Focused outbound abuse investigation."""

from __future__ import annotations

import re
import shlex
from logging import Logger

from modules.config import AssessmentConfig
from modules.models import AbuseInvestigationResult, Finding
from modules.ssh_client import RemoteClient
from modules.utils import safe_name, write_json, write_text


ABUSE_PORTS = (22, 21, 23, 587)


def run_abuse_investigation(client: RemoteClient, config: AssessmentConfig, logger: Logger) -> AbuseInvestigationResult:
    logger.info("Running outbound abuse investigation")
    result = AbuseInvestigationResult()
    command = "ss -H -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true"
    ss_result = client.run("abuse_outbound_connections", command, sudo=True, timeout=90)
    raw_path = config.paths.raw_dir / "abuse_outbound_connections.txt"
    write_text(raw_path, ss_result.stdout + "\n" + ss_result.stderr)

    pids = _extract_abuse_pids(ss_result.stdout)
    root_causes = []
    for pid, connections in pids.items():
        details = _collect_pid_details(client, pid, connections, logger)
        if details:
            root_causes.append(details)

    if root_causes:
        result.root_cause = root_causes
        severity = "Critical" if any(item.get("user") in ("www-data", "apache", "nginx", "nobody") for item in root_causes) else "High"
        result.findings.append(
            Finding(
                id="ABUSE_OUTBOUND_SERVICE_PORTS",
                title="Process originating outbound connections to abuse ports",
                severity=severity,
                confidence="High",
                category="abuse",
                description="Local processes were identified with outbound connections to SSH/FTP/Telnet/Submission ports.",
                evidence=[str(raw_path)],
                recommendation="Preserve the binary, hash, and process context; block NEW outbound traffic to abuse ports if business requirements allow it.",
                metadata={"root_cause_count": len(root_causes)},
            )
        )

    write_json(config.paths.reports_dir / "root_cause_analysis.json", root_causes)
    return result


def _extract_abuse_pids(output: str) -> dict[str, list[str]]:
    pids: dict[str, list[str]] = {}
    for line in output.splitlines():
        if "ESTAB" not in line and "SYN-SENT" not in line and "tcp" not in line.lower():
            continue
        remote = _extract_remote_endpoint(line)
        if not remote:
            continue
        pid_match = re.search(r"pid=(\d+)", line)
        if not pid_match:
            pid_match = re.search(r"/(\d+)\b", line)
        if not pid_match:
            continue
        pid = pid_match.group(1)
        pids.setdefault(pid, []).append(remote)
    return pids


def _extract_remote_endpoint(line: str) -> str | None:
    tokens = line.split()
    endpoint_tokens = [token for token in tokens if ":" in token and not token.startswith("users:")]
    if len(endpoint_tokens) >= 2:
        remote = endpoint_tokens[1].strip("[]")
        if re.search(r":(22|21|23|587)$", remote):
            return remote
    return None


def _collect_pid_details(client: RemoteClient, pid: str, connections: list[str], logger: Logger) -> dict[str, object] | None:
    quoted_pid = shlex.quote(pid)
    command = (
        f"if [ -d /proc/{quoted_pid} ]; then "
        f"echo 'PID={quoted_pid}'; "
        f"echo 'USER='$(ps -o user= -p {quoted_pid} | awk '{{print $1}}'); "
        f"echo 'LSTART='$(ps -o lstart= -p {quoted_pid}); "
        f"echo 'CMD='$(tr '\\0' ' ' < /proc/{quoted_pid}/cmdline); "
        f"echo 'EXE='$(readlink -f /proc/{quoted_pid}/exe 2>/dev/null); "
        f"exe=$(readlink -f /proc/{quoted_pid}/exe 2>/dev/null); "
        f"[ -n \"$exe\" ] && sha256sum \"$exe\" 2>/dev/null || true; "
        f"fi"
    )
    detail = client.run(f"abuse_pid_{safe_name(pid)}", command, sudo=True, timeout=60)
    if not detail.stdout.strip():
        logger.warning("PID %s disappeared before details could be collected", pid)
        return None
    path = client.config.paths.raw_dir / f"abuse_pid_{safe_name(pid)}.txt"
    write_text(path, detail.stdout + "\n" + detail.stderr)
    parsed = _parse_pid_detail(pid, detail.stdout)
    parsed["connections"] = sorted(set(connections))
    parsed["evidence"] = str(path)
    parsed["confidence"] = "HIGH"
    parsed["classification"] = _classify(parsed)
    return parsed


def _parse_pid_detail(pid: str, output: str) -> dict[str, object]:
    data: dict[str, object] = {"pid": pid}
    for line in output.splitlines():
        if line.startswith("USER="):
            data["user"] = line.split("=", 1)[1].strip()
        elif line.startswith("LSTART="):
            data["start_time"] = line.split("=", 1)[1].strip()
        elif line.startswith("CMD="):
            data["command"] = line.split("=", 1)[1].strip()
        elif line.startswith("EXE="):
            data["binary_path"] = line.split("=", 1)[1].strip()
        elif re.match(r"^[a-fA-F0-9]{64}\s+", line):
            data["sha256"] = line.split()[0]
    return data


def _classify(data: dict[str, object]) -> str:
    command = str(data.get("command", "")).lower()
    path = str(data.get("binary_path", "")).lower()
    if ":22" in " ".join(data.get("connections", [])) or "ssh" in command:
        if any(token in command for token in ("hydra", "sshpass", "medusa")) or any(
            temp in path for temp in ("/tmp", "/var/tmp", "/dev/shm")
        ):
            return "SSH Brute Force Bot"
        return "Outbound SSH Abuse Candidate"
    if ":587" in " ".join(data.get("connections", [])):
        return "Outbound Mail Submission Abuse Candidate"
    return "Outbound Abuse Candidate"
