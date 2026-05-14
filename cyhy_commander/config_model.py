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

from typing import Annotated

from pydantic import BaseModel, Field, model_validator


class JobSizingConfig(BaseModel):
    """IPs-per-job limits for each scan type.

    All values must be positive integers. These control how many IP addresses
    are bundled into a single job sent to a scanner host.
    """

    netscan1: Annotated[int, Field(gt=0, default=128)]
    netscan2: Annotated[int, Field(gt=0, default=64)]
    portscan: Annotated[int, Field(gt=0, default=8)]
    vulnscan: Annotated[int, Field(gt=0, default=4)]


class ScannerReliabilityConfig(BaseModel):
    """Scanner host error-handling settings.

    Controls how quickly a scanner host is placed on cooldown after repeated
    exceptions, and how long it remains unavailable.
    """

    exceptions_before_cooldown: Annotated[int, Field(gt=0, default=2)]
    cooldown_duration_minutes: Annotated[int, Field(gt=0, default=30)]


class TimeoutsConfig(BaseModel):
    """Network timeout settings for SSH and rsync operations.

    All values are in seconds and must be positive integers.
    The SSH connection timeout must be strictly less than the SSH command
    timeout to ensure that a slow connection attempt does not outlast the
    overall command budget.
    """

    ssh_connect: Annotated[int, Field(gt=0, default=10)]
    ssh_command: Annotated[int, Field(gt=0, default=60)]
    ssh_keepalive_interval: Annotated[int, Field(gt=0, default=30)]
    ssh_keepalive_count: Annotated[int, Field(gt=0, default=2)]
    rsync_operation: Annotated[int, Field(gt=0, default=300)]

    @model_validator(mode="after")
    def connect_less_than_command(self) -> TimeoutsConfig:
        """Validate that ssh_connect timeout is less than ssh_command timeout."""
        if self.ssh_connect >= self.ssh_command:
            raise ValueError("ssh_connect must be less than ssh_command timeout")
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
    jobs_per_nmap_host: Annotated[int, Field(gt=0, default=8)]
    jobs_per_nessus_host: Annotated[int, Field(gt=0, default=8)]
    poll_interval: Annotated[int, Field(gt=0, default=30)]
    next_scan_limit: Annotated[int, Field(gt=0, default=2000)]
    test_mode: bool = False
    keep_failures: bool = False
    keep_successes: bool = False
    shutdown_when_idle: bool = False
    log_level: str = "INFO"
    job_sizing: JobSizingConfig = Field(default_factory=JobSizingConfig)
    scanner_reliability: ScannerReliabilityConfig = Field(
        default_factory=ScannerReliabilityConfig
    )
    timeouts: TimeoutsConfig = Field(default_factory=TimeoutsConfig)
