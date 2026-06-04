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
            title="Usuarios adicionales con UID 0",
            severity="Crítico",
            confidence="Alto",
            category="usuarios",
            description=f"Se detectaron cuentas con privilegios equivalentes a root: {', '.join(non_root)}.",
            evidence=[result.evidence_path or ""],
            recommendation="Validar si las cuentas UID 0 son legítimas; deshabilitarlas si no están justificadas.",
        )
    ]


def _detect_tmp_processes(by_name: dict) -> list[Finding]:
    result = by_name.get("tmp_processes")
    if not result or not result.stdout.strip():
        return []
    return [
        Finding(
            id="PROC_TMP_EXECUTION",
            title="Procesos ejecutándose desde directorios temporales",
            severity="Alto",
            confidence="Medio",
            category="procesos",
            description="Hay procesos activos con rutas bajo /tmp, /var/tmp o /dev/shm, patrón frecuente en compromisos Linux.",
            evidence=[result.evidence_path or ""],
            recommendation="Correlacionar PID, usuario y hash; preservar el binario antes de detenerlo o cuarentenarlo.",
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
                    title=f"Indicadores conocidos detectados en {source}",
                    severity="Alto",
                    confidence="Medio",
                    category="malware",
                    description=f"Se observaron términos asociados a abuso o malware: {', '.join(hits)}.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Validar binarios, hashes y propietario del proceso antes de aplicar contención.",
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
                    title=f"Persistencia sospechosa en {source}",
                    severity="Alto" if source != "ld_preload" else "Crítico",
                    confidence="Medio",
                    category="persistencia",
                    description="Se detectaron comandos o ubicaciones compatibles con persistencia maliciosa.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Revisar entradas, preservar contenido, y deshabilitar solo tras confirmación.",
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
            title="Procesos con ejecutables eliminados",
            severity="Alto",
            confidence="Alto",
            category="procesos",
            description="Se encontraron procesos cuyo ejecutable en /proc apunta a un archivo eliminado.",
            evidence=[result.evidence_path or ""],
            recommendation="Preservar memoria/proc metadata si es posible y correlacionar con conexiones activas.",
        )
    ]


def _detect_rootkit_indicators(by_name: dict) -> list[Finding]:
    findings = []
    tools = by_name.get("rootkit_tools")
    if tools and "missing" in tools.stdout:
        findings.append(
            Finding(
                id="ROOTKIT_TOOLS_MISSING",
                title="Herramientas rootkit no disponibles",
                severity="Bajo",
                confidence="Alto",
                category="rootkit",
                description="rkhunter, chkrootkit o clamscan no están instalados en el servidor.",
                evidence=[tools.evidence_path or ""],
                recommendation="Instalar herramientas desde repositorios confiables durante remediación o en imagen forense equivalente.",
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
                    title=f"Indicadores reportados por {source}",
                    severity="Alto",
                    confidence="Medio",
                    category="rootkit",
                    description=f"La herramienta {source} reportó posibles indicadores.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Validar hallazgos manualmente y comparar contra una imagen limpia.",
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
                    title=f"Alteraciones de integridad reportadas por {source}",
                    severity="Medio",
                    confidence="Medio",
                    category="integridad",
                    description="La verificación de paquetes reportó archivos modificados o inconsistentes.",
                    evidence=[result.evidence_path or ""],
                    recommendation="Distinguir cambios administrativos legítimos de alteraciones maliciosas.",
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
                title="Evidencia de fuerza bruta SSH",
                severity="Medio",
                confidence="Alto",
                category="logs",
                description=f"Se detectaron {failed} eventos compatibles con intentos fallidos de autenticación.",
                evidence=evidence,
                recommendation="Revisar IPs origen, cuentas afectadas y correlacionar con accesos exitosos posteriores.",
                metadata={"failed_auth_events": failed, "accepted_auth_events": accepted},
            )
        )
    if useradd:
        findings.append(
            Finding(
                id="LOG_USER_CREATION",
                title="Creación de usuarios observada en logs",
                severity="Medio",
                confidence="Medio",
                category="logs",
                description=f"Se observaron {useradd} eventos compatibles con creación de usuarios.",
                evidence=evidence,
                recommendation="Validar si las altas de usuario fueron autorizadas.",
            )
        )
    if sudo >= 10:
        findings.append(
            Finding(
                id="LOG_SUDO_ACTIVITY",
                title="Actividad sudo relevante",
                severity="Bajo",
                confidence="Medio",
                category="logs",
                description=f"Se observaron {sudo} eventos sudo recientes.",
                evidence=evidence,
                recommendation="Revisar comandos sudo ejecutados durante la ventana del incidente.",
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
                title="SSH permite login directo de root",
                severity="Medio",
                confidence="Alto",
                category="accesos",
                description="La configuración efectiva de SSH indica PermitRootLogin yes.",
                evidence=[result.evidence_path or ""],
                recommendation="Deshabilitar login directo de root tras validar accesos administrativos alternativos.",
            )
        )
    if "passwordauthentication yes" in lower:
        findings.append(
            Finding(
                id="SSH_PASSWORD_AUTH_ENABLED",
                title="SSH permite autenticación por password",
                severity="Medio",
                confidence="Alto",
                category="accesos",
                description="La configuración efectiva de SSH indica PasswordAuthentication yes.",
                evidence=[result.evidence_path or ""],
                recommendation="Migrar a autenticación por clave y MFA/bastion donde aplique.",
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
