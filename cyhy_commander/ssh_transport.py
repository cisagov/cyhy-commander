"""SSH and rsync transport utilities for scanner host communication."""

import os
import shlex
import subprocess  # nosec B404
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SSHTransportConfig:
    """Configuration parameters for SSH and rsync connections."""

    connect_timeout_seconds: int = 10
    command_timeout_seconds: int = 60
    server_alive_interval_seconds: int = 30
    server_alive_count_max: int = 2
    # If you need extra ssh options, add them here like:
    # extra_ssh_args: ("-o", "IdentitiesOnly=yes", ...)
    extra_ssh_args: Sequence[str] = ()


class SSHTransport:
    """Executes remote commands and transfers files over SSH/rsync."""

    def __init__(self, logger: Any, config: SSHTransportConfig | None = None):
        """Initialize the transport with a logger and optional config."""
        self._logger = logger
        self._cfg = config or SSHTransportConfig()

    def _ssh_base(self, host: str) -> list[str]:
        # Uses user SSH config by default
        # (same intent as Fabric's env.use_ssh_config=True)
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self._cfg.connect_timeout_seconds}",
            "-o",
            f"ServerAliveInterval={self._cfg.server_alive_interval_seconds}",
            "-o",
            f"ServerAliveCountMax={self._cfg.server_alive_count_max}",
            *list(self._cfg.extra_ssh_args),
            host,
            "--",
        ]

    def _ssh_rsh(self) -> str:
        # rsync wants a single string for --rsh
        parts = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"ConnectTimeout={self._cfg.connect_timeout_seconds}",
            "-o",
            f"ServerAliveInterval={self._cfg.server_alive_interval_seconds}",
            "-o",
            f"ServerAliveCountMax={self._cfg.server_alive_count_max}",
            *list(self._cfg.extra_ssh_args),
        ]
        return shlex.join(parts)

    def _rsync_common(self) -> list[str]:
        # --archive preserves perms/symlinks/times/etc.
        # --compress helps if job bundles are text-heavy; harmless otherwise.
        # --partial keeps partial files for resume, which is helpful over flaky links.
        # --timeout is I/O timeout (seconds) for rsync itself.
        return [
            "rsync",
            "--archive",
            "--compress",
            "--partial",
            "--timeout=30",
            "--rsh",
            self._ssh_rsh(),
        ]

    def run(
        self,
        host: str,
        remote_command: str,
        timeout_seconds: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run a remote command on host via SSH and return the result."""
        timeout = (
            timeout_seconds
            if timeout_seconds is not None
            else self._cfg.command_timeout_seconds
        )
        argv = self._ssh_base(host) + [remote_command]
        self._logger.debug("SSH run: %s", shlex.join(argv))
        return subprocess.run(  # nosec B603
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def rsync_pull_dir(
        self,
        host: str,
        remote_dir: str,
        local_dir: str,
        timeout_seconds: int = 300,
    ) -> None:
        """Pull remote_dir (directory) into local_dir.

        remote_dir: e.g. "runner/done/JOB123"
        local_dir:  e.g. "done/JOB123"

        Copies remote_dir's *contents* into local_dir (trailing slash semantics).
        """
        os.makedirs(local_dir, exist_ok=True)

        src = f"{host}:{remote_dir.rstrip('/')}/"
        dst = f"{local_dir.rstrip('/')}/"

        argv = self._rsync_common() + [src, dst]
        self._logger.debug("rsync pull: %s", shlex.join(argv))

        cp = subprocess.run(  # nosec B603
            argv,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        if cp.returncode != 0:
            raise RuntimeError(
                "rsync pull failed rc={rc} stderr={stderr}".format(
                    rc=cp.returncode,
                    stderr=(cp.stderr or "").strip(),
                )
            )

    def rsync_push_dir(
        self,
        host: str,
        local_dir: str,
        remote_dir: str,
        timeout_seconds: int = 300,
    ) -> None:
        """Push local_dir (directory) into remote_dir.

        local_dir:  e.g. "/path/jobs/JOB123"
        remote_dir: e.g. "runner/running/JOB123"

        Copies local_dir's *contents* into remote_dir (trailing slash semantics).

        Requires rsync with --mkpath support.
        """
        local_dir = local_dir.rstrip("/")
        remote_dir = remote_dir.rstrip("/")

        src = f"{local_dir}/"
        dst = f"{host}:{remote_dir}/"

        argv = self._rsync_common() + ["--mkpath", src, dst]
        self._logger.debug("rsync push: %s", shlex.join(argv))

        cp = subprocess.run(  # nosec B603
            argv,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )

        if cp.returncode != 0:
            raise RuntimeError(
                "rsync push failed rc={rc} stderr={stderr}".format(
                    rc=cp.returncode,
                    stderr=(cp.stderr or "").strip(),
                )
            )
