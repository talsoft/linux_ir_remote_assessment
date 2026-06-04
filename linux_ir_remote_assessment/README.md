# linux_ir_remote_assessment

Professional remote Linux incident response assessment tool. It connects over SSH to owned or explicitly authorized Linux servers and performs safe evidence collection, indicator detection, outbound abuse investigation, and optional operator-confirmed containment.

Default mode: `collect-only`.

## Security Principles

- Use only on owned systems or systems with explicit authorization.
- No exploitation, brute force, evasion, lateral movement, or persistence.
- No system modification by default.
- Passwords, passphrases, and secrets are never stored.
- Containment requires `contain` or `full` mode and interactive confirmation.
- Operational priority: preserve evidence, contain, understand root cause, remediate.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r linux_ir_remote_assessment/requirements.txt
```

## Usage

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --password \
  --mode collect-only
```

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --key-file ~/.ssh/id_ed25519 \
  --mode detect
```

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user admin \
  --password \
  --sudo \
  --mode full \
  --abuse-investigation
```

## Authentication

Supports:

- SSH keys using RSA, ECDSA, or ED25519 through Paramiko.
- Key passphrases with `--key-passphrase`.
- Password authentication with `--password`, requested through `getpass`.
- Password fallback when `--key-file` fails and `--fallback-password` is enabled.
- Sudo detection for availability, passwordless sudo, and password-required sudo.

## Parameters

- `--host`: authorized target host.
- `--port`: SSH port, default `22`.
- `--user`: SSH username.
- `--key-file`: SSH private key.
- `--key-passphrase`: prompt for key passphrase.
- `--password`: prompt for SSH password.
- `--fallback-password`: prompt for password if key authentication fails.
- `--sudo`: use sudo for privileged commands.
- `--mode`: `collect-only`, `detect`, `contain`, `full`.
- `--output-dir`: base output directory, default `reports`.
- `--non-interactive`: do not prompt for secrets or confirmations.
- `--abuse-investigation`: force outbound abuse investigation.

## Modes

- `collect-only`: collects evidence and generates basic reports.
- `detect`: collects evidence, analyzes it, and generates findings.
- `contain`: collects, analyzes, and allows operator-confirmed containment.
- `full`: collects, detects, contains, and reports recommendations. Destructive remediation remains confirmable and is not performed automatically.

## Collected Evidence

Includes system inventory, users, access controls, SSH configuration, processes, connections, cron, systemd, shell profiles, `LD_PRELOAD`, rootkit tools when present, package integrity checks when present, authentication/syslog/journal logs, and firewall state.

Outputs are stored in:

```text
<output-dir>/<host>_<timestamp>/
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

## Abuse Report Investigation

The `abuse_investigation.py` module identifies outbound connections to:

- SSH `22`
- FTP `21`
- Telnet `23`
- Submission `587`

It correlates PID, user, binary path, SHA256 hash, full command line, process start time, and associated connections.

## Containment

Only in `contain` or `full` mode, with exact confirmation:

```text
APPLY-CONTAINMENT
```

Applied action:

- Backup of `iptables-save`, `nft list ruleset`, and `ufw status`.
- `iptables` rules that block new outbound connections to `22,21,23,587`.

The tool does not change the `OUTPUT` policy, does not close the current SSH session, and does not automatically delete processes.

## Limitations

A compromised system may hide processes, files, connections, or logs. For critical incidents with suspected rootkit activity, use this tool as an initial remote assessment and prioritize offline forensic analysis or rebuilding from a clean image.
