"""Unit tests for SSHTransport."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from cyhy_commander.ssh_transport import SSHTransport, SSHTransportConfig


class TestSSHTransportConfig:
    """Tests for SSHTransportConfig defaults."""

    def test_defaults(self):
        cfg = SSHTransportConfig()
        assert cfg.connect_timeout_seconds == 10
        assert cfg.command_timeout_seconds == 60
        assert cfg.server_alive_interval_seconds == 30
        assert cfg.server_alive_count_max == 2
        assert cfg.extra_ssh_args == ()

    def test_custom_values(self):
        cfg = SSHTransportConfig(
            connect_timeout_seconds=5,
            command_timeout_seconds=30,
            extra_ssh_args=("-o", "IdentitiesOnly=yes"),
        )
        assert cfg.connect_timeout_seconds == 5
        assert cfg.extra_ssh_args == ("-o", "IdentitiesOnly=yes")


class TestSSHTransport:
    """Tests for SSHTransport methods."""

    def setup_method(self):
        self.logger = MagicMock()
        self.ssh = SSHTransport(self.logger)

    def test_ssh_base_builds_correct_command(self):
        result = self.ssh._ssh_base("scanner1")
        assert result[0] == "ssh"
        assert "-o" in result
        assert "BatchMode=yes" in result
        assert "ConnectTimeout=10" in result
        assert "ServerAliveInterval=30" in result
        assert "ServerAliveCountMax=2" in result
        assert result[-1] == "--"
        assert "scanner1" in result

    def test_ssh_base_with_extra_args(self):
        cfg = SSHTransportConfig(extra_ssh_args=("-o", "IdentitiesOnly=yes"))
        ssh = SSHTransport(self.logger, config=cfg)
        result = ssh._ssh_base("host1")
        assert "IdentitiesOnly=yes" in result

    def test_ssh_rsh_builds_string(self):
        result = self.ssh._ssh_rsh()
        assert "ssh" in result
        assert "BatchMode=yes" in result
        assert "ConnectTimeout=10" in result

    def test_rsync_common_builds_correct_command(self):
        result = self.ssh._rsync_common()
        assert result[0] == "rsync"
        assert "--archive" in result
        assert "--compress" in result
        assert "--partial" in result
        assert "--timeout=30" in result
        assert "--rsh" in result

    @patch("cyhy_commander.ssh_transport.subprocess.run")
    def test_run_calls_subprocess(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="output", stderr=""
        )
        result = self.ssh.run("host1", "ls /tmp")
        assert result.returncode == 0
        assert result.stdout == "output"
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[1]["text"] is True
        assert call_args[1]["capture_output"] is True
        assert call_args[1]["timeout"] == 60

    @patch("cyhy_commander.ssh_transport.subprocess.run")
    def test_run_custom_timeout(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        self.ssh.run("host1", "cmd", timeout_seconds=120)
        assert mock_run.call_args[1]["timeout"] == 120

    @patch("cyhy_commander.ssh_transport.subprocess.run")
    @patch("cyhy_commander.ssh_transport.os.makedirs")
    def test_rsync_pull_dir_success(self, mock_makedirs, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        self.ssh.rsync_pull_dir("host1", "runner/done/JOB1", "done/JOB1")
        mock_makedirs.assert_called_once_with("done/JOB1", exist_ok=True)
        mock_run.assert_called_once()
        argv = mock_run.call_args[0][0]
        assert "host1:runner/done/JOB1/" in argv
        assert "done/JOB1/" in argv

    @patch("cyhy_commander.ssh_transport.subprocess.run")
    @patch("cyhy_commander.ssh_transport.os.makedirs")
    def test_rsync_pull_dir_failure(self, mock_makedirs, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        with pytest.raises(RuntimeError, match="rsync pull failed"):
            self.ssh.rsync_pull_dir("host1", "remote/dir", "local/dir")

    @patch("cyhy_commander.ssh_transport.subprocess.run")
    def test_rsync_push_dir_success(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        self.ssh.rsync_push_dir("host1", "/tmp/JOB1", "runner/running/JOB1")
        mock_run.assert_called_once()
        argv = mock_run.call_args[0][0]
        assert "--mkpath" in argv
        assert "/tmp/JOB1/" in argv
        assert "host1:runner/running/JOB1/" in argv

    @patch("cyhy_commander.ssh_transport.subprocess.run")
    def test_rsync_push_dir_failure(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="permission denied"
        )
        with pytest.raises(RuntimeError, match="rsync push failed"):
            self.ssh.rsync_push_dir("host1", "/tmp/JOB1", "remote/dir")
