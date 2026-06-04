"""Detection logic over collected evidence."""

from __future__ import annotations

import re
from logging import Logger

from modules.config import AssessmentConfig
from modules.models import CollectionResult, Finding


IOC_TERMS = (
    "xmrig",
    "kinsing",
    "mirai",
    "sshpass",
    "hydra",
    "medusa",
    "masscan",
    "zmap",
    "ncat",
    "socat",
    " nc ",
    "/nc ",
)

AUTOEXEC_TERMS = (
    "curl",
    "wget",
    "python",
    "perl",
    "bash -c",
    "base64",
    " nc ",
    "ncat",
    "socat",
    "sshpass",
)


def analyze_collected_evidence(config: AssessmentConfig, collection: CollectionResult, logger: Logger) -> list[Finding]:
    logger.info("Analyzing collected evidence")
    by_name = {item.name: item for item in collection.commands}
    findings: list[Finding] = []

    findings.extend(_detect_uid0_users(by_name))
    findings.extend(_detect_tmp_processes(by_name))
    findings.extend(_detect_iocs(by_name))
    findings.extend(_detect_persistence(by_name))
    findings.extend(_detect_deleted_executables(by_name))
    findings.extend(_detect_rootkit_indicators(by_name))
    findings.extend(_detect_integrity_findings(by_name))
    findings.extend(_detect_auth_log_abuse(by_name))
    findings.extend(_detect_ssh_config_risks(by_name))

    deduped = _dedupe(findings)
    logger.info("Analysis produced %d findings", len(deduped))
    return deduped


def _detect_uid0_users(by_name: dict) -> list[Finding]:
    result = by_name.get("uid0_users")
    if not result:
        return []
    users = [line.split(":", 1)[0] for line in result.stdout.splitlines() if line.strip()]
    non_root = [user for user in users if user != "root"]
    if not non_root:
        return []
    return [
        Finding(
            id="USER_UID0_EXTRA",
            title="Additional users with UID 0",
            severity="Critical",
            confidence="High",
            category="users",
            description=f"Accounts with root-equivalent privileges were detected: {', '.join(non_root)}.",
            evidence=[result.evidence_path or ""],
            recommendation="Validate whether the UID 0 accounts are legitimate; disable them if they are not justified.",
        )
    ]


def _detect_tmp_processes(by_name: dict) -> list[Finding]:
    result = by_name.get("tmp_processes")
    if not result or not result.stdout.strip():
        return []
    return [
        Finding(
            id="PROC_TMP_EXECUTION",
            title="Processes running from temporary directories",
            severity="High",
            confidence="Medium",
            category="processes",
            description="Active processes were found with paths under /tmp, /var/tmp, or /dev/shm, a frequent pattern in Linux compromises.",
            evidence=[result.evidence_path or ""],
            recommendation="Correlate PID, user, and hash; preserve the binary before stopping or quarantining it.",
        )
    ]


def _detect_iocs(by_name: dict) -> list[Finding]:
    findings = []
    haystack_sources = ["ps_auxf", "ss_tunap", "lsof_i", "cron", "systemd_suspicious_paths"]
    for source in haystack_sources:
        result = by_name.get(source)
        if not result:
            continue
        lower = f" {result.stdout.lower()} "
        hits = sorted({term.strip() for term in IOC_TERMS if term in lower and term.strip()})
        if hits:
            findings.append(
                Finding(
                    id=f"IOC_{source.upper()}",
                    title=f"Known indicators detected in {source}",
                    severity="High",
                    confidence="Medium",
                    category="malware",
                    description=f"Terms associated with abuse or malware were observed: {', '.join(hits)}.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Validate binaries, hashes, and process ownership before applying containment.",
                    metadata={"hits": hits, "source": source},
                )
            )
    return findings


def _detect_persistence(by_name: dict) -> list[Finding]:
    findings = []
    for source in ("cron", "systemd_suspicious_paths", "rc_profiles", "shell_profiles", "ld_preload"):
        result = by_name.get(source)
        if not result or not result.stdout.strip():
            continue
        lower = f" {result.stdout.lower()} "
        hits = sorted({term.strip() for term in AUTOEXEC_TERMS if term in lower and term.strip()})
        if hits or (source == "ld_preload" and result.stdout.strip()):
            findings.append(
                Finding(
                    id=f"PERSISTENCE_{source.upper()}",
                    title=f"Suspicious persistence in {source}",
                    severity="High" if source != "ld_preload" else "Critical",
                    confidence="Medium",
                    category="persistence",
                    description="Commands or locations compatible with malicious persistence were detected.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Review entries, preserve content, and disable only after confirmation.",
                    metadata={"hits": hits, "source": source},
                )
            )
    return findings


def _detect_deleted_executables(by_name: dict) -> list[Finding]:
    result = by_name.get("deleted_executables")
    if not result or not result.stdout.strip():
        return []
    return [
        Finding(
            id="PROC_DELETED_EXECUTABLE",
            title="Processes with deleted executables",
            severity="High",
            confidence="High",
            category="processes",
            description="Processes were found whose /proc executable link points to a deleted file.",
            evidence=[result.evidence_path or ""],
            recommendation="Preserve memory/proc metadata if possible and correlate with active connections.",
        )
    ]


def _detect_rootkit_indicators(by_name: dict) -> list[Finding]:
    findings = []
    tools = by_name.get("rootkit_tools")
    if tools and "missing" in tools.stdout:
        findings.append(
            Finding(
                id="ROOTKIT_TOOLS_MISSING",
                title="Rootkit tools not available",
                severity="Low",
                confidence="High",
                category="rootkit",
                description="rkhunter, chkrootkit, or clamscan are not installed on the server.",
                evidence=[tools.evidence_path or ""],
                recommendation="Install tools from trusted repositories during remediation or on an equivalent forensic image.",
            )
        )
    for source in ("rkhunter", "chkrootkit", "clamscan_tmp"):
        result = by_name.get(source)
        if not result or not result.stdout.strip():
            continue
        lower = result.stdout.lower()
        if any(token in lower for token in ("infected", "warning", "suspicious", "found")):
            findings.append(
                Finding(
                    id=f"ROOTKIT_{source.upper()}",
                    title=f"Indicators reported by {source}",
                    severity="High",
                    confidence="Medium",
                    category="rootkit",
                    description=f"The {source} tool reported possible indicators.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Validate findings manually and compare against a clean image.",
                )
            )
    return findings


def _detect_integrity_findings(by_name: dict) -> list[Finding]:
    findings = []
    for source in ("debsums", "rpm_va"):
        result = by_name.get(source)
        if result and result.stdout.strip():
            findings.append(
                Finding(
                    id=f"INTEGRITY_{source.upper()}",
                    title=f"Integrity changes reported by {source}",
                    severity="Medium",
                    confidence="Medium",
                    category="integrity",
                    description="Package verification reported modified or inconsistent files.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Distinguish legitimate administrative changes from malicious alterations.",
                )
            )
    return findings


def _detect_auth_log_abuse(by_name: dict) -> list[Finding]:
    findings = []
    text = "\n".join(
        result.stdout for name, result in by_name.items() if name in ("auth_logs", "journal_auth", "system_logs")
    )
    evidence = [result.evidence_path or "" for name, result in by_name.items() if name in ("auth_logs", "journal_auth", "system_logs")]
    failed = len(re.findall(r"Failed password|authentication failure|Invalid user", text, re.IGNORECASE))
    accepted = len(re.findall(r"Accepted password|Accepted publickey", text, re.IGNORECASE))
    useradd = len(re.findall(r"useradd|new user|adduser", text, re.IGNORECASE))
    sudo = len(re.findall(r"\bsudo\b.*COMMAND=", text, re.IGNORECASE))
    if failed >= 20:
        findings.append(
            Finding(
                id="LOG_BRUTE_FORCE",
                title="Evidence of SSH brute force activity",
                severity="Medium",
                confidence="High",
                category="logs",
                description=f"{failed} events compatible with failed authentication attempts were detected.",
                evidence=evidence,
                recommendation="Review source IPs, affected accounts, and correlate with later successful logins.",
                metadata={"failed_auth_events": failed, "accepted_auth_events": accepted},
            )
        )
    if useradd:
        findings.append(
            Finding(
                id="LOG_USER_CREATION",
                title="User creation observed in logs",
                severity="Medium",
                confidence="Medium",
                category="logs",
                description=f"{useradd} events compatible with user creation were observed.",
                evidence=evidence,
                recommendation="Validate whether the user creations were authorized.",
            )
        )
    if sudo >= 10:
        findings.append(
            Finding(
                id="LOG_SUDO_ACTIVITY",
                title="Relevant sudo activity",
                severity="Low",
                confidence="Medium",
                category="logs",
                description=f"{sudo} recent sudo events were observed.",
                evidence=evidence,
                recommendation="Review sudo commands executed during the incident window.",
            )
        )
    return findings


def _detect_ssh_config_risks(by_name: dict) -> list[Finding]:
    result = by_name.get("ssh_config")
    if not result:
        return []
    lower = result.stdout.lower()
    findings = []
    if "permitrootlogin yes" in lower:
        findings.append(
            Finding(
                id="SSH_ROOT_LOGIN_ENABLED",
                title="SSH allows direct root login",
                severity="Medium",
                confidence="High",
                category="access",
                description="The effective SSH configuration indicates PermitRootLogin yes.",
                evidence=[result.evidence_path or ""],
                recommendation="Disable direct root login after validating alternative administrative access.",
            )
        )
    if "passwordauthentication yes" in lower:
        findings.append(
            Finding(
                id="SSH_PASSWORD_AUTH_ENABLED",
                title="SSH allows password authentication",
                severity="Medium",
                confidence="High",
                category="access",
                description="The effective SSH configuration indicates PasswordAuthentication yes.",
                evidence=[result.evidence_path or ""],
                recommendation="Migrate to key-based authentication and MFA/bastion access where applicable.",
            )
        )
    return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    output = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        output.append(finding)
    return output
