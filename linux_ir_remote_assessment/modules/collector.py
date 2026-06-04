"""Evidence collection routines."""

from __future__ import annotations

from logging import Logger
from pathlib import Path

from modules.config import AssessmentConfig
from modules.models import CollectionResult, CommandResult
from modules.ssh_client import RemoteClient
from modules.utils import safe_name, sha256_text, write_json, write_text


COMMANDS: list[tuple[str, str, bool, int]] = [
    ("hostnamectl", "hostnamectl", False, 30),
    ("uname", "uname -a", False, 30),
    ("uptime", "uptime", False, 30),
    ("date", "date -u; date", False, 30),
    ("os_release", "cat /etc/os-release", False, 30),
    ("cpu", "lscpu 2>/dev/null || cat /proc/cpuinfo", False, 30),
    ("ram", "free -m", False, 30),
    ("filesystem", "df -h", False, 30),
    ("who", "who", False, 30),
    ("w", "w", False, 30),
    ("last", "last -a | head -n 200", False, 30),
    ("lastlog", "lastlog 2>/dev/null | head -n 300", True, 60),
    ("ip_addr", "ip addr", False, 30),
    ("ip_route", "ip route; ip -6 route 2>/dev/null", False, 30),
    ("dns", "cat /etc/resolv.conf; hostname -I 2>/dev/null", False, 30),
    ("passwd", "cat /etc/passwd", True, 30),
    ("group", "cat /etc/group", True, 30),
    ("sudoers", "cat /etc/sudoers 2>/dev/null; find /etc/sudoers.d -maxdepth 1 -type f -print -exec sed -n '1,220p' {} \\; 2>/dev/null", True, 60),
    ("ssh_config", "sshd -T 2>/dev/null || cat /etc/ssh/sshd_config 2>/dev/null", True, 60),
    ("ssh_permissions", "find /root /home -maxdepth 3 \\( -name authorized_keys -o -name .ssh \\) -printf '%m %u %g %p\\n' 2>/dev/null", True, 60),
    ("authorized_keys", "find /root /home -path '*/.ssh/authorized_keys' -type f -print -exec sed -n '1,220p' {} \\; 2>/dev/null", True, 60),
    ("interactive_users", "awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print}' /etc/passwd", True, 30),
    ("uid0_users", "awk -F: '$3 == 0 {print}' /etc/passwd", True, 30),
    ("ps_auxf", "ps auxfww", False, 60),
    ("pstree", "pstree -ap 2>/dev/null || true", False, 30),
    ("ss_tunap", "ss -tunap 2>/dev/null || true", True, 60),
    ("ss_lntup", "ss -lntup 2>/dev/null || true", True, 60),
    ("lsof_i", "lsof -nP -i 2>/dev/null | head -n 1000 || true", True, 90),
    ("netstat", "netstat -tunap 2>/dev/null || true", True, 60),
    ("tmp_processes", "ps -eo pid,ppid,user,lstart,cmd | egrep '(/tmp|/var/tmp|/dev/shm)' || true", False, 30),
    ("cron", "cat /etc/crontab 2>/dev/null; find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs -maxdepth 2 -type f -print -exec sed -n '1,220p' {} \\; 2>/dev/null", True, 90),
    ("systemd_services", "systemctl list-units --type=service --all --no-pager 2>/dev/null; systemctl list-unit-files --type=service --no-pager 2>/dev/null", True, 60),
    ("systemd_timers", "systemctl list-timers --all --no-pager 2>/dev/null; systemctl list-unit-files --type=timer --no-pager 2>/dev/null", True, 60),
    ("systemd_suspicious_paths", "find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -maxdepth 3 -print -exec grep -HnE '(/tmp|/var/tmp|/dev/shm|curl|wget|base64|bash -c|python|perl|nc|ncat|socat|sshpass)' {} \\; 2>/dev/null", True, 90),
    ("rc_profiles", "cat /etc/rc.local 2>/dev/null; cat /etc/profile 2>/dev/null; find /etc/profile.d -type f -maxdepth 1 -print -exec sed -n '1,220p' {} \\; 2>/dev/null", True, 60),
    ("shell_profiles", "find /root /home -maxdepth 2 \\( -name .bashrc -o -name .profile -o -name .bash_profile -o -name .zshrc \\) -type f -print -exec sed -n '1,180p' {} \\; 2>/dev/null", True, 90),
    ("ld_preload", "cat /etc/ld.so.preload 2>/dev/null || true", True, 30),
    ("rootkit_tools", "for t in rkhunter chkrootkit clamscan; do command -v $t >/dev/null 2>&1 && echo \"$t: present\" || echo \"$t: missing\"; done", False, 30),
    ("rkhunter", "command -v rkhunter >/dev/null 2>&1 && rkhunter --check --sk --nocolors 2>/dev/null || true", True, 300),
    ("chkrootkit", "command -v chkrootkit >/dev/null 2>&1 && chkrootkit 2>/dev/null || true", True, 300),
    ("clamscan_tmp", "command -v clamscan >/dev/null 2>&1 && clamscan -r --infected --no-summary /tmp /var/tmp /dev/shm 2>/dev/null || true", True, 300),
    ("lsmod", "lsmod", False, 30),
    ("deleted_executables", "find /proc/*/exe -lname '*deleted*' -printf '%p -> %l\\n' 2>/dev/null || true", True, 60),
    ("hidden_recent", "find /tmp /var/tmp /dev/shm /root /home -xdev -name '.*' -mtime -14 -printf '%TY-%Tm-%Td %TH:%TM %u %g %m %p\\n' 2>/dev/null | head -n 1000", True, 90),
    ("integrity_tools", "command -v debsums >/dev/null 2>&1 && echo debsums_present || true; command -v rpm >/dev/null 2>&1 && echo rpm_present || true", False, 30),
    ("debsums", "command -v debsums >/dev/null 2>&1 && debsums -s 2>/dev/null || true", True, 300),
    ("rpm_va", "command -v rpm >/dev/null 2>&1 && rpm -Va 2>/dev/null | head -n 1000 || true", True, 300),
    ("auth_logs", "for f in /var/log/auth.log /var/log/secure; do [ -f \"$f\" ] && echo \"### $f\" && tail -n 2500 \"$f\"; done", True, 90),
    ("system_logs", "for f in /var/log/syslog /var/log/messages; do [ -f \"$f\" ] && echo \"### $f\" && tail -n 1800 \"$f\"; done", True, 90),
    ("journal_auth", "journalctl -u ssh -u sshd --since '14 days ago' --no-pager 2>/dev/null | tail -n 2500 || true", True, 120),
    ("firewall_status", "iptables-save 2>/dev/null; nft list ruleset 2>/dev/null; ufw status verbose 2>/dev/null || true", True, 60),
]


def collect_evidence(client: RemoteClient, config: AssessmentConfig, logger: Logger) -> CollectionResult:
    result = CollectionResult()
    logger.info("Collecting evidence in mode=%s", config.mode)
    for name, command, privileged, timeout in COMMANDS:
        command_result = client.run(name, command, sudo=privileged, timeout=timeout)
        _persist_command(config.paths.raw_dir, command_result)
        result.commands.append(command_result)
    write_json(config.paths.evidence_index, build_evidence_index(result))
    return result


def _persist_command(raw_dir: Path, result: CommandResult) -> None:
    base = raw_dir / f"{safe_name(result.name)}.txt"
    content = (
        f"$ {result.command}\n"
        f"exit_status={result.exit_status}\n"
        f"privileged={result.privileged}\n"
        "\n--- STDOUT ---\n"
        f"{result.stdout}\n"
        "\n--- STDERR ---\n"
        f"{result.stderr}\n"
    )
    write_text(base, content)
    result.evidence_path = str(base)


def build_evidence_index(collection: CollectionResult) -> list[dict[str, object]]:
    index = []
    for command in collection.commands:
        content = f"{command.stdout}\n{command.stderr}"
        index.append(
            {
                "type": "command",
                "name": command.name,
                "command": command.command,
                "exit_status": command.exit_status,
                "privileged": command.privileged,
                "path": command.evidence_path,
                "sha256_output": sha256_text(content),
            }
        )
    index.extend(collection.files)
    return index
