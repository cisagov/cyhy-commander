"""Pydantic configuration models for cyhy-commander.

This module defines the configuration schema for the CyHy Commander application.
Configuration is loaded from a TOML file via cyhy-config and validated against
these models at startup.

Models:
    JobSizingConfig: IPs-per-job limits for each scan type.
    ScannerReliabilityConfig: Scanner host error-handling settings.
    TimeoutsConfig: Network timeout settings for SSH and rsync operations.
    CommanderConfig: Top-level commander configuration model.
"""

from pydantic import BaseModel, Field, model_validator


class JobSizingConfig(BaseModel):
    """IPs-per-job limits for each scan type.

    All values must be positive integers. These control how many IP addresses
    are bundled into a single job sent to a scanner host.
    """

    netscan1: int = Field(default=128, gt=0)
    netscan2: int = Field(default=64, gt=0)
    portscan: int = Field(default=8, gt=0)
    vulnscan: int = Field(default=4, gt=0)


class ScannerReliabilityConfig(BaseModel):
    """Scanner host error-handling settings.

    Controls how quickly a scanner host is placed on cooldown after repeated
    exceptions, and how long it remains unavailable.
    """

    exceptions_before_cooldown: int = Field(default=2, gt=0)
    cooldown_duration_minutes: int = Field(default=30, gt=0)


class TimeoutsConfig(BaseModel):
    """Network timeout settings for SSH and rsync operations.

    All values are in seconds and must be positive integers.
    The SSH connection timeout must be strictly less than the SSH command
    timeout to ensure that a slow connection attempt does not outlast the
    overall command budget.
    """

    ssh_connect: int = Field(default=10, gt=0)
    ssh_command: int = Field(default=60, gt=0)
    ssh_keepalive_interval: int = Field(default=30, gt=0)
    ssh_keepalive_count: int = Field(default=2, gt=0)
    rsync_operation: int = Field(default=300, gt=0)

    @model_validator(mode="after")
    def connect_less_than_command(self) -> TimeoutsConfig:
        """Validate that ssh_connect timeout is less than ssh_command timeout."""
        if self.ssh_connect >= self.ssh_command:
            raise ValueError(
                "ssh_connect must be less than ssh_command timeout"
            )
        return self


class CommanderConfig(BaseModel):
    """Top-level configuration model for cyhy-commander.

    Required fields (no defaults):
        mongodb_uri: MongoDB connection string.
        mongodb_database: Name of the MongoDB database to use.
        nmap_hosts: Non-empty list of nmap scanner hostnames.
        nessus_hosts: Non-empty list of Nessus scanner hostnames.

    All other fields have sensible defaults and are optional in the TOML file.
    """

    mongodb_uri: str
    mongodb_database: str
    nmap_hosts: list[str] = Field(min_length=1)
    nessus_hosts: list[str] = Field(min_length=1)
    jobs_per_nmap_host: int = Field(default=8, gt=0)
    jobs_per_nessus_host: int = Field(default=8, gt=0)
    poll_interval: int = Field(default=30, gt=0)
    next_scan_limit: int = Field(default=2000, gt=0)
    test_mode: bool = False
    keep_failures: bool = False
    keep_successes: bool = False
    shutdown_when_idle: bool = False
    log_level: str = "INFO"
    job_sizing: JobSizingConfig = Field(
        default_factory=lambda: JobSizingConfig()
    )
    scanner_reliability: ScannerReliabilityConfig = Field(
        default_factory=lambda: ScannerReliabilityConfig()
    )
    timeouts: TimeoutsConfig = Field(default_factory=lambda: TimeoutsConfig())
