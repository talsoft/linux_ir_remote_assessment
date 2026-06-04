"""SSH client wrapper with safe sudo support."""

from __future__ import annotations

import getpass
import os
import shlex
import stat
import time
from typing import Any
from logging import Logger

from modules.config import AssessmentConfig
from modules.models import CommandResult
from modules.utils import sanitize_text


class RemoteClient:
    def __init__(self, config: AssessmentConfig, logger: Logger) -> None:
        self.config = config
        self.logger = logger
        paramiko = _paramiko()
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.WarningPolicy())
        self._sudo_checked = False
        self._sudo_available = False
        self._sudo_password_required = False

    def __enter__(self) -> "RemoteClient":
        self.connect()
        if self.config.sudo:
            self.detect_sudo()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        self.client.close()

    def connect(self) -> None:
        kwargs = {
            "hostname": self.config.host,
            "port": self.config.port,
            "username": self.config.user,
            "timeout": 20,
            "banner_timeout": 20,
            "auth_timeout": 20,
            "look_for_keys": False,
            "allow_agent": False,
        }

        if self.config.key_file:
            self._validate_key_permissions()
            try:
                key = self._load_private_key()
                self.logger.info("Connecting with SSH key: %s", self.config.key_file)
                self.client.connect(pkey=key, **kwargs)
                return
            except Exception as exc:  # noqa: BLE001 - fallback path needs broad auth errors
                self.logger.warning("SSH key authentication failed: %s", exc)
                if not self.config.fallback_password:
                    raise
                if self.config.non_interactive:
                    raise RuntimeError("Key auth failed and password fallback cannot prompt in non-interactive mode.") from exc
                password = getpass.getpass("Fallback SSH password: ")
                self.client.connect(password=password, **kwargs)
                return

        if self.config.password is not None:
            self.logger.info("Connecting with SSH password")
            self.client.connect(password=self.config.password, **kwargs)
            return

        self.logger.info("Connecting with default SSH agent/key discovery disabled; password prompt required")
        if self.config.non_interactive:
            raise RuntimeError("No authentication method available in non-interactive mode.")
        password = getpass.getpass("SSH password: ")
        self.client.connect(password=password, **kwargs)

    def _validate_key_permissions(self) -> None:
        assert self.config.key_file is not None
        key_path = self.config.key_file
        if not key_path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            self.logger.warning(
                "SSH key permissions are broader than recommended: %s mode=%o. Recommended: 600.",
                key_path,
                mode,
            )

    def _load_private_key(self) -> Any:
        assert self.config.key_file is not None
        paramiko = _paramiko()
        key_path = str(self.config.key_file)
        passphrase = self.config.key_passphrase
        loaders = (
            paramiko.Ed25519Key.from_private_key_file,
            paramiko.ECDSAKey.from_private_key_file,
            paramiko.RSAKey.from_private_key_file,
        )
        last_error: Exception | None = None
        for loader in loaders:
            try:
                return loader(key_path, password=passphrase)
            except Exception as exc:  # noqa: BLE001 - try multiple key formats
                last_error = exc
        raise RuntimeError(f"Unable to load private key: {last_error}")

    def detect_sudo(self) -> None:
        if self._sudo_checked:
            return
        self._sudo_checked = True
        result = self.run("detect_sudo", "command -v sudo >/dev/null 2>&1 && echo sudo_present || echo sudo_missing")
        self._sudo_available = "sudo_present" in result.stdout
        if not self._sudo_available:
            self.logger.warning("sudo not available on target")
            return
        probe = self.run("detect_passwordless_sudo", "sudo -n true", timeout=10, allow_failure=True)
        self._sudo_password_required = probe.exit_status != 0
        if self._sudo_password_required:
            self.logger.info("sudo appears to require password")
        else:
            self.logger.info("sudo passwordless execution available")

    def run(
        self,
        name: str,
        command: str,
        *,
        sudo: bool = False,
        timeout: int = 60,
        allow_failure: bool = True,
    ) -> CommandResult:
        remote_command = command
        privileged = False
        if sudo and self.config.sudo:
            self.detect_sudo()
            if self._sudo_available:
                privileged = True
                remote_command = self._sudo_command(command)

        self.logger.info("RUN name=%s privileged=%s cmd=%s", name, privileged, sanitize_text(command))
        stdin, stdout, stderr = self.client.exec_command(remote_command, timeout=timeout, get_pty=privileged)
        if privileged and self._sudo_password_required and self.config.sudo_password:
            stdin.write(self.config.sudo_password + "\n")
            stdin.flush()
            time.sleep(0.2)
        exit_status = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        result = CommandResult(
            name=name,
            command=command,
            exit_status=exit_status,
            stdout=sanitize_text(out),
            stderr=sanitize_text(err),
            privileged=privileged,
        )
        if exit_status != 0 and not allow_failure:
            raise RuntimeError(f"Remote command failed ({name}) status={exit_status}: {err[:500]}")
        return result

    def _sudo_command(self, command: str) -> str:
        escaped = shlex.quote(command)
        if self._sudo_password_required:
            if not self.config.sudo_password:
                return f"sudo -n bash -lc {escaped}"
            return f"sudo -S -p '' bash -lc {escaped}"
        return f"sudo -n bash -lc {escaped}"


def _paramiko() -> Any:
    try:
        import paramiko  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError("Missing dependency 'paramiko'. Install with: pip install -r requirements.txt") from exc
    return paramiko
