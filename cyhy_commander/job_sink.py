"""Job sink classes for CyHy Commander.

Each sink class handles a specific type of completed scan job, parsing
results and updating the database accordingly.

Requirements: FR-1.4, MR-2.1, MR-2.8, AC-5.7
"""

# Standard Python Libraries
import glob
import logging
import os
import random

# Third-party libraries
import netaddr  # type: ignore[import-untyped]
from cyhy_db.models.enum import Stage
from cyhy_logging import CYHY_ROOT_LOGGER

# Local libraries
from cyhy_commander import db_ops
from cyhy_commander.nessus import NessusImporter
from cyhy_commander.nmap import NmapImporter

OUTPUT_FILENAME = "job.out"
TARGETS_GLOB = "*SCAN*.txt"

logger = logging.getLogger(CYHY_ROOT_LOGGER + ".commander.job_sink")


class NmapSink:
    """Handles completed nmap scan jobs (NETSCAN1, NETSCAN2, PORTSCAN).

    Delegates result parsing to NmapImporter and updates the database
    with host/port scan results and host state transitions.
    """

    def __init__(self, stage: Stage) -> None:
        """Initialise the sink for a specific nmap scan stage.

        Args:
            stage: The scan stage this sink handles (NETSCAN1, NETSCAN2,
                or PORTSCAN).
        """
        self.__stage = stage

    def __str__(self) -> str:
        """Return a string representation of this sink."""
        return f"<NmapSink {self.__stage}>"

    def can_handle(self, job_path: str) -> bool:
        """Return True if this sink can handle the job at *job_path*.

        Args:
            job_path: Path to the completed job directory.

        Returns:
            True if the job directory name starts with this sink's stage.
        """
        job_name = os.path.basename(job_path)
        return job_name.startswith(self.__stage.value)

    async def handle(self, job_path: str) -> None:
        """Parse nmap results and update the database.

        Args:
            job_path: Path to the completed job directory containing
                ``job.out`` and a targets file.
        """
        nmap_output_file = os.path.join(job_path, OUTPUT_FILENAME)
        target_glob = os.path.join(job_path, TARGETS_GLOB)
        target_file = glob.glob(target_glob)[0]
        importer = NmapImporter(self.__stage)
        await importer.process(nmap_output_file, target_file)


class NessusSink:
    """Handles completed Nessus vulnerability scan jobs (VULNSCAN).

    Delegates result parsing to NessusImporter and updates the database
    with vulnerability scan results and host state transitions.
    """

    def __str__(self) -> str:
        """Return a string representation of this sink."""
        return "<NessusSink>"

    def can_handle(self, job_path: str) -> bool:
        """Return True if this sink can handle the job at *job_path*.

        Args:
            job_path: Path to the completed job directory.

        Returns:
            True if the job directory name starts with ``VULNSCAN``.
        """
        job_name = os.path.basename(job_path)
        return job_name.startswith(Stage.VULNSCAN.value)

    async def handle(self, job_path: str) -> None:
        """Parse Nessus results and update the database.

        Args:
            job_path: Path to the completed job directory containing
                ``job.out``.
        """
        nessus_output_file = os.path.join(job_path, OUTPUT_FILENAME)
        importer = NessusImporter()
        await importer.process(nessus_output_file)


class NoOpSink:
    """A no-op sink used for testing that transitions hosts without parsing results.

    Reads the target IP list and transitions each host through the state
    machine with random up/down results (for NETSCAN stages) or a simple
    transition (for other stages).
    """

    def __str__(self) -> str:
        """Return a string representation of this sink."""
        return "<NoOpSink>"

    async def __transition_ip_file(
        self, filename: str, random_up_downs: bool = False
    ) -> None:
        """Transition all IPs listed in *filename*.

        Args:
            filename: Path to a file containing one IP address per line.
            random_up_downs: If True, randomly assign up/down status to
                each host.  If False, all hosts are transitioned as down.
        """
        with open(filename) as f:
            for ip_line in f:
                ip = str(netaddr.IPAddress(ip_line.strip()))
                if random_up_downs:
                    up = random.choice([True, False])  # nosec B311
                    reason = "syn-ack" if up else "no-response"
                    await db_ops.transition_host(ip, up=up, reason=reason)
                else:
                    await db_ops.transition_host(ip, up=False, reason="noop")

    def can_handle(self, job_path: str) -> bool:
        """Return True — the NoOpSink handles any job.

        Args:
            job_path: Path to the completed job directory.

        Returns:
            Always True.
        """
        return True

    async def handle(self, job_path: str) -> None:
        """Transition all target IPs without parsing scan results.

        Args:
            job_path: Path to the completed job directory containing a
                targets file.
        """
        target_glob = os.path.join(job_path, TARGETS_GLOB)
        target_file = glob.glob(target_glob)[0]
        job_name = os.path.basename(job_path)
        if job_name.startswith(Stage.NETSCAN1.value) or job_name.startswith(
            Stage.NETSCAN2.value
        ):
            await self.__transition_ip_file(target_file, random_up_downs=True)
        else:
            await self.__transition_ip_file(target_file, random_up_downs=False)


class TryAgainSink:
    """A failure sink that marks all target hosts as scan failures.

    Used when a job fails and the hosts should be returned to WAITING
    status so they can be retried.
    """

    def __init__(self) -> None:
        """Initialise the TryAgainSink."""
        self.__logger = logging.getLogger(
            CYHY_ROOT_LOGGER + ".commander.job_sink"
        )

    def __str__(self) -> str:
        """Return a string representation of this sink."""
        return "<TryAgainSink>"

    def can_handle(self, job_path: str) -> bool:
        """Return True — the TryAgainSink handles any failed job.

        Args:
            job_path: Path to the failed job directory.

        Returns:
            Always True.
        """
        return True

    async def handle(self, job_path: str) -> None:
        """Mark all target IPs as scan failures so they are retried.

        Reads the target file and calls ``db_ops.transition_host`` with
        ``was_failure=True`` for each IP, which causes the host state
        machine to revert the host to WAITING status.

        Args:
            job_path: Path to the failed job directory containing a
                targets file.
        """
        target_glob = os.path.join(job_path, TARGETS_GLOB)
        target_file = glob.glob(target_glob)[0]
        with open(target_file) as f:
            for ip_line in f:
                # It's possible that the target file contains hostnames, so
                # check if any targets are a hostname and an IP address (e.g.
                # "foo.gov[192.168.1.1]"), and if so, extract the IP address.
                #
                # This could be done via regex, but there is no benefit that
                # justifies the additional import.  Note that if something
                # other than a valid IP is in the brackets, casting to an
                # IPAddress will fail regardless of how we parse it.
                if "[" in ip_line:
                    parts = ip_line.strip().split("[")
                    if len(parts) == 2 and parts[1].endswith("]"):
                        ip_line = parts[1][:-1]
                    else:
                        self.__logger.warning(
                            "Skipping malformed target '%s' in job %s",
                            ip_line.strip(),
                            job_path,
                        )
                        continue
                ip = str(netaddr.IPAddress(ip_line.strip()))
                await db_ops.transition_host(
                    ip, up=False, reason="scan-failure", was_failure=True
                )
