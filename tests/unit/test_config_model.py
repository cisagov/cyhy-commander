"""Unit tests for CommanderConfig Pydantic models.

Covers valid configuration round-trips, missing required fields, the
ssh_connect >= ssh_command model validator, and default values for all
optional fields.

Requirements: AC-8.1, FR-5.5
"""

import pytest
from pydantic import ValidationError

from cyhy_commander.config_model import (
    CommanderConfig,
    JobSizingConfig,
    ScannerReliabilityConfig,
    TimeoutsConfig,
)

# ---------------------------------------------------------------------------
# Minimal valid data helpers
# ---------------------------------------------------------------------------

_MINIMAL_COMMANDER = {
    "mongodb_uri": "mongodb://localhost:27017/",
    "mongodb_database": "cyhy",
    "nmap_hosts": ["scanner1.example.com"],
    "nessus_hosts": ["nessus1.example.com"],
}


# ---------------------------------------------------------------------------
# JobSizingConfig
# ---------------------------------------------------------------------------


class TestJobSizingConfig:
    """Tests for JobSizingConfig."""

    def test_default_values(self):
        """All fields have the correct defaults when none are supplied."""
        cfg = JobSizingConfig()
        assert cfg.netscan1 == 128
        assert cfg.netscan2 == 64
        assert cfg.portscan == 8
        assert cfg.vulnscan == 4

    def test_explicit_values_round_trip(self):
        """Explicitly supplied values are preserved exactly."""
        cfg = JobSizingConfig(netscan1=256, netscan2=128, portscan=16, vulnscan=8)
        assert cfg.netscan1 == 256
        assert cfg.netscan2 == 128
        assert cfg.portscan == 16
        assert cfg.vulnscan == 8

    @pytest.mark.parametrize("field", ["netscan1", "netscan2", "portscan", "vulnscan"])
    def test_zero_value_raises(self, field):
        """Zero is not a valid value (gt=0 constraint)."""
        with pytest.raises(ValidationError):
            JobSizingConfig(**{field: 0})

    @pytest.mark.parametrize("field", ["netscan1", "netscan2", "portscan", "vulnscan"])
    def test_negative_value_raises(self, field):
        """Negative values are not valid (gt=0 constraint)."""
        with pytest.raises(ValidationError):
            JobSizingConfig(**{field: -1})

    @pytest.mark.parametrize("field", ["netscan1", "netscan2", "portscan", "vulnscan"])
    def test_positive_value_accepted(self, field):
        """Any positive integer is accepted."""
        cfg = JobSizingConfig(**{field: 1})
        assert getattr(cfg, field) == 1


# ---------------------------------------------------------------------------
# ScannerReliabilityConfig
# ---------------------------------------------------------------------------


class TestScannerReliabilityConfig:
    """Tests for ScannerReliabilityConfig."""

    def test_default_values(self):
        """All fields have the correct defaults when none are supplied."""
        cfg = ScannerReliabilityConfig()
        assert cfg.exceptions_before_cooldown == 2
        assert cfg.cooldown_duration_minutes == 30

    def test_explicit_values_round_trip(self):
        """Explicitly supplied values are preserved exactly."""
        cfg = ScannerReliabilityConfig(
            exceptions_before_cooldown=5, cooldown_duration_minutes=60
        )
        assert cfg.exceptions_before_cooldown == 5
        assert cfg.cooldown_duration_minutes == 60

    @pytest.mark.parametrize(
        "field", ["exceptions_before_cooldown", "cooldown_duration_minutes"]
    )
    def test_zero_value_raises(self, field):
        """Zero is not a valid value (gt=0 constraint)."""
        with pytest.raises(ValidationError):
            ScannerReliabilityConfig(**{field: 0})

    @pytest.mark.parametrize(
        "field", ["exceptions_before_cooldown", "cooldown_duration_minutes"]
    )
    def test_negative_value_raises(self, field):
        """Negative values are not valid (gt=0 constraint)."""
        with pytest.raises(ValidationError):
            ScannerReliabilityConfig(**{field: -5})


# ---------------------------------------------------------------------------
# TimeoutsConfig — defaults and round-trips
# ---------------------------------------------------------------------------


class TestTimeoutsConfigDefaults:
    """TimeoutsConfig default values."""

    def test_default_values(self):
        """All fields have the correct defaults when none are supplied."""
        cfg = TimeoutsConfig()
        assert cfg.ssh_connect == 10
        assert cfg.ssh_command == 60
        assert cfg.ssh_keepalive_interval == 30
        assert cfg.ssh_keepalive_count == 2
        assert cfg.rsync_operation == 300

    def test_explicit_values_round_trip(self):
        """Explicitly supplied values are preserved exactly."""
        cfg = TimeoutsConfig(
            ssh_connect=5,
            ssh_command=120,
            ssh_keepalive_interval=15,
            ssh_keepalive_count=3,
            rsync_operation=600,
        )
        assert cfg.ssh_connect == 5
        assert cfg.ssh_command == 120
        assert cfg.ssh_keepalive_interval == 15
        assert cfg.ssh_keepalive_count == 3
        assert cfg.rsync_operation == 600

    @pytest.mark.parametrize(
        "field",
        [
            "ssh_connect",
            "ssh_command",
            "ssh_keepalive_interval",
            "ssh_keepalive_count",
            "rsync_operation",
        ],
    )
    def test_zero_value_raises(self, field):
        """Zero is not a valid value (gt=0 constraint)."""
        # Build a valid base dict and override the target field.
        base = {
            "ssh_connect": 5,
            "ssh_command": 60,
            "ssh_keepalive_interval": 30,
            "ssh_keepalive_count": 2,
            "rsync_operation": 300,
        }
        base[field] = 0
        with pytest.raises(ValidationError):
            TimeoutsConfig(**base)

    @pytest.mark.parametrize(
        "field",
        [
            "ssh_connect",
            "ssh_command",
            "ssh_keepalive_interval",
            "ssh_keepalive_count",
            "rsync_operation",
        ],
    )
    def test_negative_value_raises(self, field):
        """Negative values are not valid (gt=0 constraint)."""
        base = {
            "ssh_connect": 5,
            "ssh_command": 60,
            "ssh_keepalive_interval": 30,
            "ssh_keepalive_count": 2,
            "rsync_operation": 300,
        }
        base[field] = -1
        with pytest.raises(ValidationError):
            TimeoutsConfig(**base)


# ---------------------------------------------------------------------------
# TimeoutsConfig — ssh_connect >= ssh_command validator
# ---------------------------------------------------------------------------


class TestTimeoutsConfigValidator:
    """Tests for the connect_less_than_command model validator."""

    def test_connect_equal_to_command_raises(self):
        """ssh_connect == ssh_command must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            TimeoutsConfig(ssh_connect=60, ssh_command=60)
        assert "ssh_connect must be less than ssh_command" in str(exc_info.value)

    def test_connect_greater_than_command_raises(self):
        """ssh_connect > ssh_command must raise ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            TimeoutsConfig(ssh_connect=120, ssh_command=60)
        assert "ssh_connect must be less than ssh_command" in str(exc_info.value)

    def test_connect_less_than_command_is_valid(self):
        """ssh_connect < ssh_command is valid and must not raise."""
        cfg = TimeoutsConfig(ssh_connect=5, ssh_command=60)
        assert cfg.ssh_connect == 5
        assert cfg.ssh_command == 60

    def test_connect_one_less_than_command_is_valid(self):
        """ssh_connect exactly one second less than ssh_command is valid."""
        cfg = TimeoutsConfig(ssh_connect=59, ssh_command=60)
        assert cfg.ssh_connect == 59
        assert cfg.ssh_command == 60

    def test_default_values_satisfy_validator(self):
        """Default ssh_connect (10) < default ssh_command (60) — no error."""
        cfg = TimeoutsConfig()
        assert cfg.ssh_connect < cfg.ssh_command

    def test_validator_error_message_is_descriptive(self):
        """ValidationError message identifies the violated constraint."""
        with pytest.raises(ValidationError) as exc_info:
            TimeoutsConfig(ssh_connect=30, ssh_command=30)
        errors = exc_info.value.errors()
        # At least one error should reference the validator
        messages = [e["msg"] for e in errors]
        assert any("ssh_connect" in m for m in messages)


# ---------------------------------------------------------------------------
# CommanderConfig — required fields
# ---------------------------------------------------------------------------


class TestCommanderConfigRequiredFields:
    """Missing required fields must raise ValidationError."""

    def test_valid_minimal_config(self):
        """A config with all required fields and no optional fields is valid."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.mongodb_uri == "mongodb://localhost:27017/"
        assert cfg.mongodb_database == "cyhy"
        assert cfg.nmap_hosts == ["scanner1.example.com"]
        assert cfg.nessus_hosts == ["nessus1.example.com"]

    def test_missing_mongodb_uri_raises(self):
        """Omitting mongodb_uri raises ValidationError."""
        data = {k: v for k, v in _MINIMAL_COMMANDER.items() if k != "mongodb_uri"}
        with pytest.raises(ValidationError) as exc_info:
            CommanderConfig(**data)
        assert "mongodb_uri" in str(exc_info.value)

    def test_missing_mongodb_database_raises(self):
        """Omitting mongodb_database raises ValidationError."""
        data = {
            k: v for k, v in _MINIMAL_COMMANDER.items() if k != "mongodb_database"
        }
        with pytest.raises(ValidationError) as exc_info:
            CommanderConfig(**data)
        assert "mongodb_database" in str(exc_info.value)

    def test_missing_nmap_hosts_raises(self):
        """Omitting nmap_hosts raises ValidationError."""
        data = {k: v for k, v in _MINIMAL_COMMANDER.items() if k != "nmap_hosts"}
        with pytest.raises(ValidationError) as exc_info:
            CommanderConfig(**data)
        assert "nmap_hosts" in str(exc_info.value)

    def test_missing_nessus_hosts_raises(self):
        """Omitting nessus_hosts raises ValidationError."""
        data = {k: v for k, v in _MINIMAL_COMMANDER.items() if k != "nessus_hosts"}
        with pytest.raises(ValidationError) as exc_info:
            CommanderConfig(**data)
        assert "nessus_hosts" in str(exc_info.value)

    def test_empty_nmap_hosts_raises(self):
        """An empty nmap_hosts list raises ValidationError (min_length=1)."""
        data = {**_MINIMAL_COMMANDER, "nmap_hosts": []}
        with pytest.raises(ValidationError):
            CommanderConfig(**data)

    def test_empty_nessus_hosts_raises(self):
        """An empty nessus_hosts list raises ValidationError (min_length=1)."""
        data = {**_MINIMAL_COMMANDER, "nessus_hosts": []}
        with pytest.raises(ValidationError):
            CommanderConfig(**data)

    def test_multiple_nmap_hosts_accepted(self):
        """Multiple nmap hosts are accepted."""
        data = {
            **_MINIMAL_COMMANDER,
            "nmap_hosts": ["scanner1.example.com", "scanner2.example.com"],
        }
        cfg = CommanderConfig(**data)
        assert len(cfg.nmap_hosts) == 2

    def test_multiple_nessus_hosts_accepted(self):
        """Multiple nessus hosts are accepted."""
        data = {
            **_MINIMAL_COMMANDER,
            "nessus_hosts": ["nessus1.example.com", "nessus2.example.com"],
        }
        cfg = CommanderConfig(**data)
        assert len(cfg.nessus_hosts) == 2


# ---------------------------------------------------------------------------
# CommanderConfig — default values for optional fields
# ---------------------------------------------------------------------------


class TestCommanderConfigDefaults:
    """All optional fields have the correct default values."""

    def test_jobs_per_nmap_host_default(self):
        """jobs_per_nmap_host defaults to 8."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.jobs_per_nmap_host == 8

    def test_jobs_per_nessus_host_default(self):
        """jobs_per_nessus_host defaults to 8."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.jobs_per_nessus_host == 8

    def test_poll_interval_default(self):
        """poll_interval defaults to 30."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.poll_interval == 30

    def test_next_scan_limit_default(self):
        """next_scan_limit defaults to 2000."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.next_scan_limit == 2000

    def test_test_mode_default(self):
        """test_mode defaults to False."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.test_mode is False

    def test_keep_failures_default(self):
        """keep_failures defaults to False."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.keep_failures is False

    def test_keep_successes_default(self):
        """keep_successes defaults to False."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.keep_successes is False

    def test_shutdown_when_idle_default(self):
        """shutdown_when_idle defaults to False."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.shutdown_when_idle is False

    def test_log_level_default(self):
        """log_level defaults to 'INFO'."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert cfg.log_level == "INFO"

    def test_job_sizing_default(self):
        """job_sizing defaults to a JobSizingConfig with standard defaults."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert isinstance(cfg.job_sizing, JobSizingConfig)
        assert cfg.job_sizing.netscan1 == 128
        assert cfg.job_sizing.netscan2 == 64
        assert cfg.job_sizing.portscan == 8
        assert cfg.job_sizing.vulnscan == 4

    def test_scanner_reliability_default(self):
        """scanner_reliability defaults to a ScannerReliabilityConfig with standard defaults."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert isinstance(cfg.scanner_reliability, ScannerReliabilityConfig)
        assert cfg.scanner_reliability.exceptions_before_cooldown == 2
        assert cfg.scanner_reliability.cooldown_duration_minutes == 30

    def test_timeouts_default(self):
        """timeouts defaults to a TimeoutsConfig with standard defaults."""
        cfg = CommanderConfig(**_MINIMAL_COMMANDER)
        assert isinstance(cfg.timeouts, TimeoutsConfig)
        assert cfg.timeouts.ssh_connect == 10
        assert cfg.timeouts.ssh_command == 60
        assert cfg.timeouts.ssh_keepalive_interval == 30
        assert cfg.timeouts.ssh_keepalive_count == 2
        assert cfg.timeouts.rsync_operation == 300


# ---------------------------------------------------------------------------
# CommanderConfig — optional field constraints
# ---------------------------------------------------------------------------


class TestCommanderConfigOptionalConstraints:
    """Optional integer fields must be positive (gt=0)."""

    @pytest.mark.parametrize(
        "field",
        [
            "jobs_per_nmap_host",
            "jobs_per_nessus_host",
            "poll_interval",
            "next_scan_limit",
        ],
    )
    def test_zero_value_raises(self, field):
        """Zero is not valid for positive-integer optional fields."""
        data = {**_MINIMAL_COMMANDER, field: 0}
        with pytest.raises(ValidationError):
            CommanderConfig(**data)

    @pytest.mark.parametrize(
        "field",
        [
            "jobs_per_nmap_host",
            "jobs_per_nessus_host",
            "poll_interval",
            "next_scan_limit",
        ],
    )
    def test_negative_value_raises(self, field):
        """Negative values are not valid for positive-integer optional fields."""
        data = {**_MINIMAL_COMMANDER, field: -1}
        with pytest.raises(ValidationError):
            CommanderConfig(**data)

    @pytest.mark.parametrize(
        "field",
        [
            "jobs_per_nmap_host",
            "jobs_per_nessus_host",
            "poll_interval",
            "next_scan_limit",
        ],
    )
    def test_positive_value_accepted(self, field):
        """Any positive integer is accepted for optional integer fields."""
        data = {**_MINIMAL_COMMANDER, field: 1}
        cfg = CommanderConfig(**data)
        assert getattr(cfg, field) == 1


# ---------------------------------------------------------------------------
# CommanderConfig — full round-trip with all fields specified
# ---------------------------------------------------------------------------


class TestCommanderConfigFullRoundTrip:
    """A fully-specified config round-trips without loss."""

    def test_full_config_round_trip(self):
        """All fields survive a round-trip through CommanderConfig."""
        data = {
            "mongodb_uri": "mongodb://user:pass@host:27017/",
            "mongodb_database": "cyhy_prod",
            "nmap_hosts": ["nmap1.example.com", "nmap2.example.com"],
            "nessus_hosts": ["nessus1.example.com"],
            "jobs_per_nmap_host": 16,
            "jobs_per_nessus_host": 4,
            "poll_interval": 60,
            "next_scan_limit": 5000,
            "test_mode": True,
            "keep_failures": True,
            "keep_successes": True,
            "shutdown_when_idle": True,
            "log_level": "DEBUG",
            "job_sizing": {
                "netscan1": 256,
                "netscan2": 128,
                "portscan": 16,
                "vulnscan": 8,
            },
            "scanner_reliability": {
                "exceptions_before_cooldown": 5,
                "cooldown_duration_minutes": 60,
            },
            "timeouts": {
                "ssh_connect": 5,
                "ssh_command": 120,
                "ssh_keepalive_interval": 15,
                "ssh_keepalive_count": 4,
                "rsync_operation": 600,
            },
        }
        cfg = CommanderConfig(**data)

        assert cfg.mongodb_uri == "mongodb://user:pass@host:27017/"
        assert cfg.mongodb_database == "cyhy_prod"
        assert cfg.nmap_hosts == ["nmap1.example.com", "nmap2.example.com"]
        assert cfg.nessus_hosts == ["nessus1.example.com"]
        assert cfg.jobs_per_nmap_host == 16
        assert cfg.jobs_per_nessus_host == 4
        assert cfg.poll_interval == 60
        assert cfg.next_scan_limit == 5000
        assert cfg.test_mode is True
        assert cfg.keep_failures is True
        assert cfg.keep_successes is True
        assert cfg.shutdown_when_idle is True
        assert cfg.log_level == "DEBUG"
        assert cfg.job_sizing.netscan1 == 256
        assert cfg.job_sizing.netscan2 == 128
        assert cfg.job_sizing.portscan == 16
        assert cfg.job_sizing.vulnscan == 8
        assert cfg.scanner_reliability.exceptions_before_cooldown == 5
        assert cfg.scanner_reliability.cooldown_duration_minutes == 60
        assert cfg.timeouts.ssh_connect == 5
        assert cfg.timeouts.ssh_command == 120
        assert cfg.timeouts.ssh_keepalive_interval == 15
        assert cfg.timeouts.ssh_keepalive_count == 4
        assert cfg.timeouts.rsync_operation == 600

    def test_nested_timeout_validator_propagates_through_commander_config(self):
        """ssh_connect >= ssh_command in nested timeouts raises from CommanderConfig."""
        data = {
            **_MINIMAL_COMMANDER,
            "timeouts": {
                "ssh_connect": 60,
                "ssh_command": 60,
            },
        }
        with pytest.raises(ValidationError):
            CommanderConfig(**data)

    def test_nested_job_sizing_constraint_propagates(self):
        """Zero value in nested job_sizing raises from CommanderConfig."""
        data = {
            **_MINIMAL_COMMANDER,
            "job_sizing": {"netscan1": 0},
        }
        with pytest.raises(ValidationError):
            CommanderConfig(**data)
