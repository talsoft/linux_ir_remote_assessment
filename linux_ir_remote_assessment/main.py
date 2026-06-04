#!/usr/bin/env python3
"""Linux IR Remote Assessment entrypoint."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from modules.abuse_investigation import run_abuse_investigation
from modules.analyzer import analyze_collected_evidence
from modules.collector import collect_evidence
from modules.config import AssessmentConfig
from modules.containment import run_containment
from modules.logging_setup import configure_logging
from modules.reporter import generate_reports
from modules.ssh_client import RemoteClient
from modules.utils import ensure_output_tree, utc_timestamp


VALID_MODES = ("collect-only", "detect", "contain", "full")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="linux_ir_remote_assessment",
        description="Remote Linux incident response assessment over authorized SSH.",
    )
    parser.add_argument("--host", required=True, help="Authorized target host or IP.")
    parser.add_argument("--port", type=int, default=22, help="SSH port. Default: 22.")
    parser.add_argument("--user", required=True, help="SSH username.")
    parser.add_argument("--key-file", help="Private key path for SSH authentication.")
    parser.add_argument("--key-passphrase", action="store_true", help="Prompt for SSH key passphrase.")
    parser.add_argument("--password", action="store_true", help="Prompt for SSH password.")
    parser.add_argument(
        "--fallback-password",
        action="store_true",
        help="Prompt for password if key authentication fails.",
    )
    parser.add_argument("--sudo", action="store_true", help="Use sudo for privileged collection commands.")
    parser.add_argument("--mode", choices=VALID_MODES, default="collect-only", help="Assessment mode.")
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Base output directory. A timestamped assessment folder is created inside it.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt. Requires all confirmations/secrets to be supplied by safe mechanisms.",
    )
    parser.add_argument(
        "--abuse-investigation",
        action="store_true",
        help="Run focused outbound SSH/FTP/mail abuse investigation.",
    )
    return parser.parse_args()


def prompt_secret(label: str, non_interactive: bool) -> str | None:
    if non_interactive:
        return None
    value = getpass.getpass(label)
    return value if value else None


def build_config(args: argparse.Namespace) -> AssessmentConfig:
    key_file = Path(args.key_file).expanduser() if args.key_file else None
    key_passphrase = None
    if args.key_passphrase:
        key_passphrase = prompt_secret("SSH key passphrase: ", args.non_interactive)

    password = None
    if args.password:
        password = prompt_secret("SSH password: ", args.non_interactive)

    sudo_password = None
    if args.sudo:
        sudo_password = prompt_secret("Sudo password (press Enter if passwordless sudo is expected): ", args.non_interactive)

    assessment_id = utc_timestamp()
    output_root = Path(args.output_dir).expanduser().resolve() / f"{args.host}_{assessment_id}"
    paths = ensure_output_tree(output_root)

    return AssessmentConfig(
        host=args.host,
        port=args.port,
        user=args.user,
        key_file=key_file,
        key_passphrase=key_passphrase,
        password=password,
        fallback_password=args.fallback_password,
        sudo=args.sudo,
        sudo_password=sudo_password,
        mode=args.mode,
        output_root=output_root,
        paths=paths,
        non_interactive=args.non_interactive,
        abuse_investigation=args.abuse_investigation,
        assessment_id=assessment_id,
    )


def main() -> int:
    args = parse_args()
    config = build_config(args)
    logger = configure_logging(config.paths.commands_log)

    logger.info("Starting authorized Linux IR remote assessment")
    logger.info("Target: %s:%s user=%s mode=%s", config.host, config.port, config.user, config.mode)

    if config.non_interactive and (args.password or args.key_passphrase or args.sudo):
        logger.error("Non-interactive mode cannot prompt for password, key passphrase, or sudo password.")
        return 2

    if config.mode in ("contain", "full") and config.non_interactive:
        logger.error("Containment/full modes require interactive confirmation in this version.")
        return 2

    try:
        with RemoteClient(config, logger) as client:
            collection = collect_evidence(client, config, logger)
            findings = []
            root_cause = []
            actions = []

            if config.mode in ("detect", "contain", "full"):
                findings = analyze_collected_evidence(config, collection, logger)

            if config.abuse_investigation or config.mode in ("detect", "contain", "full"):
                abuse_result = run_abuse_investigation(client, config, logger)
                root_cause = abuse_result.root_cause
                findings.extend(abuse_result.findings)

            if config.mode in ("contain", "full"):
                actions = run_containment(client, config, findings, logger)

            generate_reports(config, collection, findings, root_cause, actions, logger)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as exc:  # noqa: BLE001 - top-level CLI error boundary
        logger.exception("Assessment failed: %s", exc)
        return 1

    logger.info("Assessment completed. Output: %s", config.output_root)
    print(f"\nAssessment completed: {config.output_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
