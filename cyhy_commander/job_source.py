"""Job source classes for CyHy Commander.

Provides abstractions for fetching scan jobs from a directory or from the
database.  The database-backed source uses Beanie models directly and the
db_ops module to atomically claim READY hosts.

Requirements: FR-1.1, MR-2.1, MR-2.8, AC-5.7
"""

import logging
import os
import shutil
import tempfile
from datetime import datetime, timezone

from cyhy_db.models import HostDoc, PortScanDoc
from cyhy_db.models.enum import Stage, Status

from . import db_ops
from cyhy_logging import CYHY_ROOT_LOGGER

logger = logging.getLogger(CYHY_ROOT_LOGGER + ".commander.job_source")

JOB_FILENAME = "job"
PORTS_FILE_NAME = "ports"


def _utcnow() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _list_to_range_string(ports: list[int]) -> str:
    """Convert a sorted list of port numbers to a compact range string.

    For example, [80, 443, 8000, 8001, 8002] → "80,443,8000-8002".

    Args:
        ports: A list of integer port numbers (need not be sorted).

    Returns:
        A comma-separated string of individual ports and contiguous ranges.
    """
    if not ports:
        return ""

    sorted_ports = sorted(set(ports))
    ranges: list[str] = []
    start = sorted_ports[0]
    end = sorted_ports[0]

    for port in sorted_ports[1:]:
        if port == end + 1:
            end = port
        else:
            ranges.append(str(start) if start == end else f"{start}-{end}")
            start = port
            end = port

    ranges.append(str(start) if start == end else f"{start}-{end}")
    return ",".join(ranges)


class JobSource:
    """Abstract base class for job sources."""

    def __init__(self):
        """Initialize the job source."""
        pass

    def get_job(self):
        """Return the next job path, or False if none available."""
        return False


class DirectoryJobSource(JobSource):
    """A job source that reads pre-built job directories from the filesystem."""

    def __init__(self, directory: str):
        """Initialize the directory job source.

        Args:
            directory: Path to the directory containing queued job directories.
        """
        self.__directory = directory
        if not os.path.exists(directory):
            os.makedirs(directory)

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return "<DirectoryJobSource %s>" % (self.__directory)

    def get_job(self):
        """Return the path to the next queued job directory, or None."""
        return self.__get_queued_job()

    def __get_queued_job(self):
        jobs = os.listdir(self.__directory)
        if len(jobs) == 0:
            return None
        job = jobs.pop()
        job_path = os.path.join(self.__directory, job)
        return job_path


class DatabaseJobSource(JobSource):
    """A job source that fetches READY hosts from the database.

    Uses db_ops.fetch_ready_hosts to atomically claim hosts and builds a
    temporary job directory containing the scan job script and a target list.
    """

    def __init__(
        self,
        job_file: str,
        job_type: Stage = Stage.NETSCAN1,
        count: int = 32,
    ):
        """Initialize the database job source.

        Args:
            job_file: Path to the scan job script to copy into each job bundle.
            job_type: The scan stage (NETSCAN1, NETSCAN2, PORTSCAN, VULNSCAN).
            count: Maximum number of hosts to include in a single job bundle.
        """
        self.__job_file = job_file
        self.__job_type = job_type
        self.__count = count
        self.__temp_dir = tempfile.mkdtemp()

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return "<DatabaseJobSource %s>" % (self.__job_type)

    def __del__(self):
        """Clean up the temporary directory on garbage collection."""
        shutil.rmtree(self.__temp_dir, ignore_errors=True)

    def get_job(self):
        """Return the path to a newly created job directory, or None.

        Note: This method is synchronous but internally calls async helpers.
        The caller (commander.py) is responsible for awaiting the async
        make_job() coroutine directly.  This synchronous wrapper exists for
        backward compatibility with the DirectoryJobSource interface.
        """
        # The async version (make_job) is called directly by commander.py.
        # This stub satisfies the base-class interface.
        return None

    async def make_job(self) -> str | None:
        """Fetch READY hosts and build a job directory bundle.

        Atomically claims up to ``self.__count`` READY hosts for
        ``self.__job_type``, writes a target list, and copies the job script
        into a temporary directory.

        Returns:
            The path to the job directory, or None if no hosts are available.
        """
        hosts: list[HostDoc] = await db_ops.fetch_ready_hosts(
            count=self.__count,
            stage=self.__job_type,
        )
        if not hosts:
            return None

        # Create the job directory.
        date = _utcnow().isoformat().replace(":", "").replace("-", "")
        dir_name = "{}-{}".format(self.__job_type.value, date)
        job_path = os.path.join(self.__temp_dir, dir_name)
        os.mkdir(job_path)

        # Copy in the job script.
        job_file_path = os.path.join(job_path, JOB_FILENAME)
        shutil.copyfile(self.__job_file, job_file_path)

        # Write the target list.
        target_file_name = "%s.txt" % dir_name
        target_path = os.path.join(job_path, target_file_name)
        with open(target_path, "w") as target_file:
            if self.__job_type == Stage.VULNSCAN:
                # Vulnerability scans use IP addresses only (HostDoc has no
                # hostnames field in the current cyhy-db schema).
                for host in hosts:
                    print(str(host.ip), file=target_file)
            else:
                for host in hosts:
                    print(str(host.ip), file=target_file)

        # Vulnerability scans also require a port list file.
        if self.__job_type == Stage.VULNSCAN:
            ip_list = [host.ip for host in hosts]
            open_ports = await PortScanDoc.find(
                PortScanDoc.ip.in_(ip_list),
                PortScanDoc.latest == True,  # noqa: E712
                PortScanDoc.state == "open",
            ).to_list()
            port_numbers = sorted({doc.port for doc in open_ports})
            ports_string = _list_to_range_string(port_numbers)
            ports_path = os.path.join(job_path, PORTS_FILE_NAME)
            with open(ports_path, "w") as ports_file:
                print(ports_string, file=ports_file)

        logger.debug(
            "Created job bundle %s with %d hosts for stage %s.",
            dir_name,
            len(hosts),
            self.__job_type,
            extra={"job": dir_name, "stage": self.__job_type.value},
        )
        return job_path
