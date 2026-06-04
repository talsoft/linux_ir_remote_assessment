# linux_ir_remote_assessment

Professional incident response tool for remote assessments of authorized Linux servers over SSH.

The goal is to help Talsoft TS consultants collect evidence, detect indicators of compromise, investigate outbound SSH/FTP/Telnet/Submission abuse, identify persistence, and generate executive and technical reports without modifying the target system by default.

Default mode: `collect-only`.

## Authorized Use

Use this tool only on systems you own or systems where the client or asset owner has granted explicit authorization.

The tool does not include offensive capabilities: it does not exploit vulnerabilities, perform brute force attacks, evade controls, perform lateral movement, or install persistence.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r linux_ir_remote_assessment/requirements.txt
```

## Usage Examples

Evidence collection without modifying the system:

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --password \
  --mode collect-only
```

Detection using an SSH key:

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --key-file ~/.ssh/id_ed25519 \
  --mode detect
```

Full assessment with sudo and outbound abuse investigation:

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user admin \
  --password \
  --sudo \
  --mode full \
  --abuse-investigation
```

## Modes

- `collect-only`: collects evidence and generates basic artifacts.
- `detect`: collects evidence, analyzes indicators, and generates findings.
- `contain`: collects, analyzes, and allows operator-confirmed containment.
- `full`: collects, detects, contains, and reports remediation recommendations.

## Core Capabilities

- System, network, user, process, and connection inventory.
- Review of SSH access, `authorized_keys`, sudoers, and UID 0 accounts.
- Detection of processes running from `/tmp`, `/var/tmp`, and `/dev/shm`.
- Investigation of outbound connections to ports `22`, `21`, `23`, and `587`.
- Detection of suspicious cron jobs, systemd services, timers, shell profiles, and `LD_PRELOAD`.
- Execution of `rkhunter`, `chkrootkit`, `clamscan`, `debsums`, and `rpm -Va` when already present on the system.
- Basic analysis of authentication, sudo, SSH, and user-creation logs.
- Executive and technical reports in Markdown, HTML, and JSON.

## Generated Artifacts

Each execution creates a timestamped folder under the output directory:

```text
reports/<host>_<timestamp>/
├── commands.log
├── evidence_index.json
├── evidence/
│   └── raw/
└── reports/
    ├── report.md
    ├── report.html
    ├── findings.json
    ├── ioc_report.json
    └── root_cause_analysis.json
```

## Containment

Containment runs only in `contain` or `full` mode and requires exact interactive confirmation.

Supported actions:

- Backup of `iptables`, `nftables`, and `ufw` state.
- Blocking new outbound connections to common abuse ports.

The tool does not change the `OUTPUT` policy, does not close the current SSH session, and does not automatically delete processes.

## Structure

```text
linux_ir_remote_assessment/
├── main.py
├── modules/
├── reports/
├── templates/
├── evidence/
├── README.md
└── requirements.txt
```

## Operational Recommendations

- Run `collect-only` first to preserve evidence.
- Use `detect` when the objective is to generate automated findings without making changes.
- Use `--sudo` when the client authorizes privileged reads of logs, cron, sudoers, and system evidence.
- Preserve suspicious binaries and hashes before stopping processes or quarantining files.
- If rootkit activity or altered system binaries are suspected, prioritize rebuilding from a clean image.

## Limitations

Remote analysis depends on the integrity of the examined host. A compromised system may hide processes, files, connections, or logs. For critical incidents, use this tool as an initial assessment and complement it with offline forensic analysis.
