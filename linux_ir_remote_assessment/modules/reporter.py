"""Report generation."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from logging import Logger

from modules.config import AssessmentConfig
from modules.models import CollectionResult, Finding
from modules.utils import severity_rank, write_json, write_text


def generate_reports(
    config: AssessmentConfig,
    collection: CollectionResult,
    findings: list[Finding],
    root_cause: list[dict[str, object]],
    actions: list[dict[str, object]],
    logger: Logger,
) -> None:
    logger.info("Generating reports")
    findings_sorted = sorted(findings, key=lambda item: severity_rank(item.severity), reverse=True)
    risk = _overall_risk(findings_sorted)

    write_json(config.paths.reports_dir / "findings.json", [asdict(finding) for finding in findings_sorted])
    write_json(config.paths.reports_dir / "ioc_report.json", _ioc_report(findings_sorted))
    if not (config.paths.reports_dir / "root_cause_analysis.json").exists():
        write_json(config.paths.reports_dir / "root_cause_analysis.json", root_cause)

    md = _markdown_report(config, collection, findings_sorted, root_cause, actions, risk)
    report_md = config.paths.reports_dir / "report.md"
    report_html = config.paths.reports_dir / "report.html"
    write_text(report_md, md)
    write_text(report_html, _html_report(md))
    logger.info("Reports written: %s %s", report_md, report_html)


def _overall_risk(findings: list[Finding]) -> str:
    if any(finding.severity.lower() == "critical" for finding in findings):
        return "Critical"
    if any(finding.severity.lower() == "high" for finding in findings):
        return "High"
    if any(finding.severity.lower() == "medium" for finding in findings):
        return "Medium"
    return "Low"


def _ioc_report(findings: list[Finding]) -> dict[str, object]:
    indicators = []
    for finding in findings:
        if finding.category in ("malware", "abuse", "processes", "persistence", "rootkit"):
            indicators.append(asdict(finding))
    return {"indicator_count": len(indicators), "indicators": indicators}


def _markdown_report(
    config: AssessmentConfig,
    collection: CollectionResult,
    findings: list[Finding],
    root_cause: list[dict[str, object]],
    actions: list[dict[str, object]],
    risk: str,
) -> str:
    lines = [
        "# Linux IR Remote Assessment Report",
        "",
        "## 1. Executive Summary",
        "",
        f"Assessment ID: `{config.assessment_id}`",
        f"Target: `{config.host}:{config.port}`",
        f"User: `{config.user}`",
        f"Mode: `{config.mode}`",
        f"Overall risk rating: **{risk}**",
        "",
        "This assessment collected remote Linux evidence over authorized SSH. The default workflow preserves evidence first, then supports detection and optional containment when explicitly confirmed.",
        "",
        "## 2. Risk Rating",
        "",
        f"**{risk}**",
        "",
        "## 3. Key Findings",
        "",
    ]
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severity: {finding.severity}",
                    f"- Confidence: {finding.confidence}",
                    f"- Category: {finding.category}",
                    f"- Description: {finding.description}",
                    f"- Recommendation: {finding.recommendation or 'Review manually.'}",
                    f"- Evidence: {', '.join(finding.evidence) if finding.evidence else 'N/A'}",
                    "",
                ]
            )
    else:
        lines.extend(["No automated findings were generated in this execution.", ""])

    lines.extend(["## 4. Root Cause Analysis", ""])
    if root_cause:
        for item in root_cause:
            lines.extend(
                [
                    f"- Process/PID: `{item.get('pid', 'N/A')}`",
                    f"- User: `{item.get('user', 'N/A')}`",
                    f"- Path: `{item.get('binary_path', 'N/A')}`",
                    f"- SHA256: `{item.get('sha256', 'N/A')}`",
                    f"- Command: `{item.get('command', 'N/A')}`",
                    f"- Start time: `{item.get('start_time', 'N/A')}`",
                    f"- Connections: {', '.join(item.get('connections', [])) if isinstance(item.get('connections'), list) else 'N/A'}",
                    f"- Confidence level: {item.get('confidence', 'N/A')}",
                    f"- Classification: {item.get('classification', 'N/A')}",
                    "",
                ]
            )
    else:
        lines.extend(["No outbound abuse root-cause process was automatically identified.", ""])

    category_sections = [
        ("## 5. Suspicious Processes", "processes"),
        ("## 6. Suspicious Connections", "abuse"),
        ("## 7. Users and Access", "users"),
        ("## 8. Detected Persistence", "persistence"),
        ("## 9. Malware Indicators", "malware"),
        ("## 10. Rootkit Indicators", "rootkit"),
    ]
    for title, category in category_sections:
        lines.extend([title, ""])
        matching = [finding for finding in findings if finding.category == category]
        if matching:
            lines.extend([f"- {finding.severity}: {finding.title}" for finding in matching])
        else:
            lines.append("No automated findings in this category.")
        lines.append("")

    lines.extend(["## 11. Firewall Status", ""])
    fw = _command_path(collection, "firewall_status")
    lines.extend([f"Evidence: `{fw or 'N/A'}`", ""])

    lines.extend(["## 12. Applied Actions", ""])
    if actions:
        lines.append("```json")
        lines.append(json.dumps(actions, indent=2, default=str))
        lines.append("```")
    else:
        lines.append("No containment or remediation actions were applied.")
    lines.append("")

    lines.extend(
        [
            "## 13. Immediate Recommendations",
            "",
            "- Preserve collected evidence and do not delete suspicious binaries before hashing them.",
            "- Block unnecessary outbound traffic to ports 22, 21, 23, and 587 if business requirements allow it.",
            "- Rotate credentials and review authorized SSH keys.",
            "- If there is evidence of rootkit activity or altered system binaries, prioritize rebuilding from a clean image.",
            "",
            "## 14. Hardening Recommendations",
            "",
            "- Disable PasswordAuthentication and PermitRootLogin after validating alternative access.",
            "- Implement Fail2Ban or equivalent SSH controls.",
            "- Maintain EDR/antimalware coverage and centralized logging.",
            "- Restrict egress traffic with explicit firewall rules based on business need.",
            "",
            "## 15. Collected Evidence",
            "",
            f"- Index: `{config.paths.evidence_index}`",
            f"- Commands: `{config.paths.commands_log}`",
            f"- Raw evidence: `{config.paths.raw_dir}`",
            "",
            "## 16. Analysis Limitations",
            "",
            "- Remote analysis depends on the integrity of the compromised system.",
            "- An active rootkit may hide processes, files, or connections.",
            "- rkhunter/chkrootkit/clamscan/debsums/rpm tools run only if they already exist.",
            "",
            "## 17. Next Steps",
            "",
            "- Manually review high-severity findings.",
            "- Correlate with perimeter logs, cloud logs, provider portal data, and abuse reports.",
            "- Decide whether to remediate or rebuild based on scope, persistence, and confidence in system integrity.",
            "",
        ]
    )
    return "\n".join(lines)


def _command_path(collection: CollectionResult, name: str) -> str | None:
    for command in collection.commands:
        if command.name == name:
            return command.evidence_path
    return None


def _html_report(markdown: str) -> str:
    body = []
    for line in markdown.splitlines():
        escaped = html.escape(line)
        if line.startswith("# "):
            body.append(f"<h1>{escaped[2:]}</h1>")
        elif line.startswith("## "):
            body.append(f"<h2>{escaped[3:]}</h2>")
        elif line.startswith("### "):
            body.append(f"<h3>{escaped[4:]}</h3>")
        elif line.startswith("- "):
            body.append(f"<p>{escaped}</p>")
        elif line == "":
            body.append("")
        else:
            body.append(f"<p>{escaped}</p>")
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Linux IR Remote Assessment Report</title>"
        "<style>body{font-family:Arial,sans-serif;line-height:1.5;max-width:1120px;margin:32px auto;padding:0 24px;color:#1f2933}"
        "h1,h2,h3{color:#102a43}code{background:#f0f4f8;padding:2px 4px;border-radius:4px}"
        "p{margin:8px 0}</style></head><body>"
        + "\n".join(body)
        + "</body></html>"
    )
