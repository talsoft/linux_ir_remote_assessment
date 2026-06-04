"""Report generation."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from logging import Logger
from pathlib import Path

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
    if any(finding.severity.lower() in ("crítico", "critico") for finding in findings):
        return "Crítico"
    if any(finding.severity.lower() == "alto" for finding in findings):
        return "Alto"
    if any(finding.severity.lower() == "medio" for finding in findings):
        return "Medio"
    return "Bajo"


def _ioc_report(findings: list[Finding]) -> dict[str, object]:
    indicators = []
    for finding in findings:
        if finding.category in ("malware", "abuse", "procesos", "persistencia", "rootkit"):
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
        "## 3. Hallazgos Principales",
        "",
    ]
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severidad: {finding.severity}",
                    f"- Confianza: {finding.confidence}",
                    f"- Categoría: {finding.category}",
                    f"- Descripción: {finding.description}",
                    f"- Recomendación: {finding.recommendation or 'Revisar manualmente.'}",
                    f"- Evidencia: {', '.join(finding.evidence) if finding.evidence else 'N/A'}",
                    "",
                ]
            )
    else:
        lines.extend(["No se generaron hallazgos automáticos en esta ejecución.", ""])

    lines.extend(["## 4. Root Cause Analysis", ""])
    if root_cause:
        for item in root_cause:
            lines.extend(
                [
                    f"- Proceso/PID: `{item.get('pid', 'N/A')}`",
                    f"- Usuario: `{item.get('user', 'N/A')}`",
                    f"- Ruta: `{item.get('binary_path', 'N/A')}`",
                    f"- SHA256: `{item.get('sha256', 'N/A')}`",
                    f"- Comando: `{item.get('command', 'N/A')}`",
                    f"- Inicio: `{item.get('start_time', 'N/A')}`",
                    f"- Conexiones: {', '.join(item.get('connections', [])) if isinstance(item.get('connections'), list) else 'N/A'}",
                    f"- Nivel de confianza: {item.get('confidence', 'N/A')}",
                    f"- Clasificación: {item.get('classification', 'N/A')}",
                    "",
                ]
            )
    else:
        lines.extend(["No se identificó automáticamente un proceso raíz de abuso saliente.", ""])

    category_sections = [
        ("## 5. Procesos Sospechosos", "procesos"),
        ("## 6. Conexiones Sospechosas", "abuse"),
        ("## 7. Usuarios y Accesos", "usuarios"),
        ("## 8. Persistencia Detectada", "persistencia"),
        ("## 9. Malware Indicators", "malware"),
        ("## 10. Rootkit Indicators", "rootkit"),
    ]
    for title, category in category_sections:
        lines.extend([title, ""])
        matching = [finding for finding in findings if finding.category == category]
        if matching:
            lines.extend([f"- {finding.severity}: {finding.title}" for finding in matching])
        else:
            lines.append("Sin hallazgos automáticos en esta categoría.")
        lines.append("")

    lines.extend(["## 11. Firewall Status", ""])
    fw = _command_path(collection, "firewall_status")
    lines.extend([f"Evidencia: `{fw or 'N/A'}`", ""])

    lines.extend(["## 12. Acciones Aplicadas", ""])
    if actions:
        lines.append("```json")
        lines.append(json.dumps(actions, indent=2, default=str))
        lines.append("```")
    else:
        lines.append("No se aplicaron acciones de contención/remediación.")
    lines.append("")

    lines.extend(
        [
            "## 13. Recomendaciones Inmediatas",
            "",
            "- Preservar evidencia recolectada y no eliminar binarios sospechosos antes de hashearlos.",
            "- Bloquear salidas no necesarias a puertos 22, 21, 23, 25, 465 y 587 si el negocio lo permite.",
            "- Rotar credenciales y revisar llaves SSH autorizadas.",
            "- Si existe evidencia de rootkit o binarios del sistema alterados, priorizar reconstrucción desde imagen limpia.",
            "",
            "## 14. Recomendaciones de Hardening",
            "",
            "- Deshabilitar PasswordAuthentication y PermitRootLogin tras validar accesos alternativos.",
            "- Implementar Fail2Ban o controles equivalentes en SSH.",
            "- Mantener EDR/antimalware y logging centralizado.",
            "- Restringir egreso por firewall con reglas explícitas por necesidad.",
            "",
            "## 15. Evidencias Recolectadas",
            "",
            f"- Índice: `{config.paths.evidence_index}`",
            f"- Comandos: `{config.paths.commands_log}`",
            f"- Evidencia cruda: `{config.paths.raw_dir}`",
            "",
            "## 16. Limitaciones del Análisis",
            "",
            "- El análisis remoto depende de la integridad del sistema comprometido.",
            "- Un rootkit activo podría ocultar procesos, archivos o conexiones.",
            "- Las herramientas rkhunter/chkrootkit/clamscan/debsums/rpm solo se ejecutan si ya existen.",
            "",
            "## 17. Próximos Pasos",
            "",
            "- Revisar manualmente hallazgos de alta severidad.",
            "- Correlacionar con logs perimetrales, cloud, panel del proveedor y reportes de abuso.",
            "- Definir si conviene remediar o reconstruir según alcance, persistencia y confianza en integridad.",
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
