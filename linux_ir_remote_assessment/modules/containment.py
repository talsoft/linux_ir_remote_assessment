"""Optional containment actions."""

from __future__ import annotations

from logging import Logger

from modules.config import AssessmentConfig
from modules.models import Finding
from modules.ssh_client import RemoteClient
from modules.utils import utc_timestamp, write_json, write_text


ABUSE_PORTS = (22, 21, 23, 587)


def run_containment(
    client: RemoteClient,
    config: AssessmentConfig,
    findings: list[Finding],
    logger: Logger,
) -> list[dict[str, object]]:
    logger.info("Containment mode requested")
    print("\nContainment will add outbound NEW blocking rules for ports: 22, 21, 23, 587.")
    print("It will first collect firewall backups and will not change OUTPUT default policy.")
    answer = input("Type APPLY-CONTAINMENT to continue: ").strip()
    if answer != "APPLY-CONTAINMENT":
        logger.info("Containment not confirmed by operator")
        return [{"action": "containment", "status": "skipped", "reason": "operator did not confirm"}]

    timestamp = utc_timestamp()
    actions: list[dict[str, object]] = []
    backup = client.run(
        "firewall_backup_before_containment",
        "echo '### iptables-save'; iptables-save 2>/dev/null; echo '### nft'; nft list ruleset 2>/dev/null; echo '### ufw'; ufw status verbose 2>/dev/null || true",
        sudo=True,
        timeout=60,
    )
    backup_path = config.paths.evidence_dir / f"firewall_backup_{timestamp}.txt"
    write_text(backup_path, backup.stdout + "\n" + backup.stderr)
    actions.append({"action": "firewall_backup", "status": "completed", "evidence": str(backup_path)})

    for port in ABUSE_PORTS:
        cmd = (
            f"iptables -C OUTPUT -p tcp --dport {port} -m conntrack --ctstate NEW -j REJECT 2>/dev/null "
            f"|| iptables -A OUTPUT -p tcp --dport {port} -m conntrack --ctstate NEW -j REJECT"
        )
        res = client.run(f"contain_block_outbound_{port}", cmd, sudo=True, timeout=30)
        status = "completed" if res.exit_status == 0 else "failed"
        actions.append(
            {
                "action": "block_outbound_new",
                "port": port,
                "status": status,
                "exit_status": res.exit_status,
                "stderr": res.stderr[-500:],
            }
        )

    write_json(config.paths.reports_dir / "containment_actions.json", actions)
    logger.info("Containment actions recorded")
    return actions
