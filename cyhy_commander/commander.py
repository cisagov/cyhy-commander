#!/usr/bin/env python3

"""Cyber Hygiene commander.

Feeds scanners jobs, processes output, and stores results in database.
"""

import argparse
import asyncio
from collections import defaultdict
import logging
import os
from pathlib import Path, PurePosixPath
import random
import shlex
import shutil
import signal
import sys
import time
import traceback

import cyhy_db
from cyhy_config import get_config
from cyhy_db.models.enum import ScanType, Stage
from cyhy_logging import CYHY_ROOT_LOGGER, setup_logging

from .config_model import CommanderConfig
from . import db_ops

# Default owner constant — "ownerless" hosts belong to this org.
# Sourced from db_ops to keep a single definition.
DEFAULT_OWNER = db_ops.DEFAULT_OWNER

from .job_sink import NmapSink, NessusSink, TryAgainSink, NoOpSink
from .job_source import DirectoryJobSource, DatabaseJobSource
from . import ssh_transport

# remote files
DONE_DIR = "runner/done"
DONE_FILE = ".done"
READY_FILE = ".ready"
RUNNING_DIR = "runner/running"

# local files
DEFAULT_LOGGER_LEVEL = logging.INFO
DROP_DIR = "drop"
FAILED_DIR = "failed"
LOCK_FILENAME = "cyhy-commander"
PUSHED_DIR = "pushed"
STOP_FILE = "stop"
SUCCESS_DIR = "done"

# local job files
_jobs_dir = Path(__file__).resolve().parent / "jobs"
# BASESCAN_JOB_FILE removed — BASESCAN support dropped per spec
NETSCAN1_JOB_FILE = _jobs_dir / "netscan1.sh"
NETSCAN2_JOB_FILE = _jobs_dir / "netscan2.sh"
PORTSCAN_JOB_FILE = _jobs_dir / "portscan.sh"
SLEEP_JOB_FILE = _jobs_dir / "rand-sleep.py"
VULNSCAN_JOB_FILE = _jobs_dir / "vulnscan.py"

RANDOMIZE_SOURCES = True

NESSUS_WORKGROUP = "nessus"
NMAP_WORKGROUP = "nmap"


class Commander(object):
    def __init__(self, config: CommanderConfig):
        # Set up logging first in order to log any errors as soon as possible.
        self.__logger = logging.getLogger(CYHY_ROOT_LOGGER + ".commander")

        self.__all_hosts_idle = False
        self.__config = config
        self.__db = None
        self.__failed_job_queue = None
        self.__failure_sinks = []
        self.__host_exceptions = defaultdict(lambda: 0)
        self.__hosts_on_cooldown = []
        self.__is_running = True
        self.__keep_failures = config.keep_failures
        self.__keep_successes = config.keep_successes
        self.__log_output_sleep_duration = 10
        self.__nessus_sources = []
        self.__next_scan_limit = config.next_scan_limit
        self.__nmap_sources = []
        self.__setup_directories()
        self.__shutdown_when_idle = config.shutdown_when_idle
        self.__success_sinks = []
        self.__successful_job_queue = None
        self.__test_mode = config.test_mode

        # New SSH transport (Fabric replacement)
        self.__ssh = ssh_transport.SSHTransport(self.__logger)

    def __setup_directories(self):
        for directory in (SUCCESS_DIR, PUSHED_DIR, FAILED_DIR):
            path = Path(directory)
            if not path.exists():
                self.__logger.info('Creating directory "%s".' % (directory))
                path.mkdir(parents=True)


    def __setup_sources(self):
        if self.__test_mode:
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=Stage.NETSCAN1,
                    count=self.__config.job_sizing.netscan1,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=Stage.NETSCAN2,
                    count=self.__config.job_sizing.netscan2,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=Stage.PORTSCAN,
                    count=self.__config.job_sizing.portscan,
                )
            )
            self.__nessus_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=Stage.VULNSCAN,
                    count=self.__config.job_sizing.vulnscan,
                )
            )
        else:
            self.__nessus_sources.append(DirectoryJobSource(DROP_DIR))
            self.__nmap_sources.append(
                DatabaseJobSource(
                    NETSCAN1_JOB_FILE,
                    self.__db,
                    job_type=Stage.NETSCAN1,
                    count=self.__config.job_sizing.netscan1,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    NETSCAN2_JOB_FILE,
                    self.__db,
                    job_type=Stage.NETSCAN2,
                    count=self.__config.job_sizing.netscan2,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    PORTSCAN_JOB_FILE,
                    self.__db,
                    job_type=Stage.PORTSCAN,
                    count=self.__config.job_sizing.portscan,
                )
            )
            self.__nessus_sources.append(
                DatabaseJobSource(
                    VULNSCAN_JOB_FILE,
                    self.__db,
                    job_type=Stage.VULNSCAN,
                    count=self.__config.job_sizing.vulnscan,
                )
            )

    def __setup_sinks(self):
        if self.__test_mode:
            noop_sink = NoOpSink()
            self.__success_sinks.append(noop_sink)
        else:
            netscan1_sink = NmapSink(Stage.NETSCAN1)
            netscan2_sink = NmapSink(Stage.NETSCAN2)
            portscan_sink = NmapSink(Stage.PORTSCAN)
            vulnscan_sink = NessusSink()
            self.__success_sinks.extend(
                (netscan1_sink, netscan2_sink, portscan_sink, vulnscan_sink)
            )
        self.__failure_sinks = [TryAgainSink()]

    async def __done_jobs(self, host: str) -> None:
        try:
            cp = await asyncio.to_thread(
                self.__ssh.run, host, "ls {d}".format(d=shlex.quote(DONE_DIR))
            )
            if cp.returncode != 0:
                self.__logger.warning(
                    'Unable to get listing of "%s" on %s: %s',
                    DONE_DIR,
                    host,
                    (cp.stderr or "").strip(),
                )
                return

            done_jobs = (cp.stdout or "").split()
            for job in done_jobs:
                job_path = str(PurePosixPath(DONE_DIR) / job)
                done_path = str(PurePosixPath(job_path) / DONE_FILE)

                # Only proceed when .done exists and has an exit code.
                cp_done = await asyncio.to_thread(
                    self.__ssh.run,
                    host,
                    "test -f {p} && cat {p} || true".format(p=shlex.quote(done_path)),
                )
                exit_code = (cp_done.stdout or "").strip()
                # Derive the stage from the job name prefix (e.g. "NETSCAN1-…")
                _job_stage = job.split("-")[0] if "-" in job else job

                if not exit_code:
                    self.__logger.warning(
                        "%s is not ready for pickup on %s",
                        job,
                        host,
                        extra={"host": host, "job": job, "stage": _job_stage},
                    )
                    continue

                self.__logger.info(
                    "%s is ready for pickup on %s",
                    job,
                    host,
                    extra={"host": host, "job": job, "stage": _job_stage},
                )

                if exit_code == "0":
                    dest_dir = SUCCESS_DIR
                else:
                    dest_dir = FAILED_DIR
                    self.__logger.warning(
                        "%s had a non-zero exit code: %s",
                        job,
                        exit_code,
                        extra={"host": host, "job": job, "stage": _job_stage},
                    )

                local_job_dir = str(Path(dest_dir) / job)
                await asyncio.to_thread(
                    self.__ssh.rsync_pull_dir,
                    host=host,
                    remote_dir=job_path,
                    local_dir=local_job_dir,
                )

                self.__logger.info(
                    "%s was copied successfully from %s to %s",
                    job,
                    host,
                    dest_dir,
                    extra={"host": host, "job": job, "stage": _job_stage},
                )

                # remove remote dir
                cp_rm = await asyncio.to_thread(
                    self.__ssh.run, host, "rm -rf {p}".format(p=shlex.quote(job_path))
                )
                if cp_rm.returncode == 0:
                    self.__logger.info(
                        "%s was removed from %s",
                        job,
                        host,
                        extra={"host": host, "job": job, "stage": _job_stage},
                    )
                else:
                    self.__logger.warning(
                        "Unable to remove %s from %s: %s",
                        job_path,
                        host,
                        (cp_rm.stderr or "").strip(),
                        extra={"host": host, "job": job, "stage": _job_stage},
                    )

                if dest_dir == SUCCESS_DIR:
                    self.__successful_job_queue.put_nowait(local_job_dir)
                else:
                    self.__failed_job_queue.put_nowait(local_job_dir)

        except Exception as e:
            self.__logger.error("Exception when retrieving done jobs from %s", host)
            self.__logger.error(e)
            self.__host_exceptions[host] += 1

    async def __running_job_count(self, host: str):
        try:
            cp = await asyncio.to_thread(
                self.__ssh.run, host, "ls {d}".format(d=shlex.quote(RUNNING_DIR))
            )
            if cp.returncode != 0:
                self.__logger.warning(
                    'Unable to get listing of "%s" on %s: %s',
                    RUNNING_DIR,
                    host,
                    (cp.stderr or "").strip(),
                )
                return None
            running_jobs = (cp.stdout or "").split()
            return len(running_jobs)
        except Exception as e:
            self.__logger.error("Exception when retrieving running job count from %s", host)
            self.__logger.error(e)
            self.__host_exceptions[host] += 1
            return None

    async def __push_job(self, host: str, job_path: str) -> None:
        try:
            job_name = Path(job_path.rstrip("/")).name
            remote_job_dir = str(PurePosixPath(RUNNING_DIR) / job_name)
            # Derive stage from job name prefix (e.g. "NETSCAN1-…")
            _job_stage = job_name.split("-")[0] if "-" in job_name else job_name

            await asyncio.to_thread(
                self.__ssh.rsync_push_dir,
                host=host,
                local_dir=job_path,
                remote_dir=remote_job_dir,
            )

            self.__logger.info(
                "%s was pushed successfully to %s",
                job_path,
                host,
                extra={"host": host, "job": job_name, "stage": _job_stage},
            )

            cp_touch = await asyncio.to_thread(
                self.__ssh.run,
                host,
                "touch {p}".format(p=shlex.quote(str(PurePosixPath(remote_job_dir) / READY_FILE))),
            )
            if cp_touch.returncode != 0:
                self.__logger.error(
                    "Error touching %s on host %s: %s",
                    os.path.join(remote_job_dir, READY_FILE),
                    host,
                    (cp_touch.stderr or "").strip(),
                    extra={"host": host, "job": job_name, "stage": _job_stage},
                )
                self.__host_exceptions[host] += 1
                return

            self.__move_to_pushed(job_path)

        except Exception as e:
            self.__logger.error("Exception when pushing %s to host %s", job_path, host)
            self.__logger.error(e)
            self.__host_exceptions[host] += 1

    def __unique_filename(self, path):
        p = Path(path)
        if not p.exists():
            return str(p)
        new_name = "%s.%d" % (p.name, int(time.time() * 1000000))
        return str(p.with_name(new_name))


    def __move_to_pushed(self, job_path):
        if not self.__test_mode:
            shutil.rmtree(job_path)
            self.__logger.info("%s deleted" % job_path)
        else:
            dest = str(Path(PUSHED_DIR) / Path(job_path).name)
            dest = self.__unique_filename(dest)
            shutil.move(job_path, dest)
            self.__logger.info("%s moved locally to %s" % (job_path, dest))

    def __lowest_host(self, counts):
        lowest_count = None
        lowest_host = None
        for (host, count) in counts.items():
            if count != None and (lowest_count == None or count < lowest_count):
                lowest_host = host
                lowest_count = count
        return lowest_host

    def __job_from_sources(self, sources):
        job = None
        if RANDOMIZE_SOURCES:
            random.shuffle(sources)
        for source in sources:
            self.__logger.debug("Checking %s for a job." % source)
            job = source.get_job()
            if job != None:
                self.__logger.info("Acquired a job from %s" % source)
                break
            self.__logger.debug("No available jobs returned by %s" % source)
        return job

    async def __fill_hosts(self, counts, sources, workgroup_name, jobs_per_host):
        while True:
            lowest_host = self.__lowest_host(counts)
            if counts[lowest_host] >= jobs_per_host:
                self.__logger.debug("All %s hosts are full" % workgroup_name)
                break  # everyone is full
            job_path = self.__job_from_sources(sources)
            if job_path == None:
                self.__logger.debug(
                    "Not enough work available to fill %s hosts" % workgroup_name
                )
                break  # no more work to do
            await self.__push_job(lowest_host, job_path)
            counts[lowest_host] += 1

    async def __process_successful_job(self, job_path: str) -> None:
        """Process a single successful job using the registered success sinks."""
        job_name = Path(job_path).name
        _job_stage = job_name.split("-")[0] if "-" in job_name else job_name
        for sink in self.__success_sinks:
            if sink.can_handle(job_path):
                self.__logger.info(
                    "Processing %s with %s",
                    job_path,
                    sink,
                    extra={"job": job_name, "stage": _job_stage},
                )
                sink.handle(job_path)
                self.__logger.info(
                    "Processing completed for %s",
                    job_path,
                    extra={"job": job_name, "stage": _job_stage},
                )
                if not self.__test_mode and not self.__keep_successes:
                    shutil.rmtree(job_path)
                    self.__logger.info("%s deleted", job_path)
                return
        self.__logger.warning("No handler was able to process %s", job_path)

    async def __process_failed_job(self, job_path: str) -> None:
        """Process a single failed job using the registered failure sinks."""
        job_name = Path(job_path).name
        _job_stage = job_name.split("-")[0] if "-" in job_name else job_name
        for sink in self.__failure_sinks:
            if sink.can_handle(job_path):
                self.__logger.warning(
                    "Processing %s with %s",
                    job_path,
                    sink,
                    extra={"job": job_name, "stage": _job_stage},
                )
                sink.handle(job_path)
                self.__logger.info(
                    "Processing completed for %s",
                    job_path,
                    extra={"job": job_name, "stage": _job_stage},
                )
                if not self.__test_mode and not self.__keep_failures:
                    shutil.rmtree(job_path)
                    self.__logger.info("%s deleted", job_path)
                return
        self.__logger.warning("No handler was able to process %s", job_path)

    def handle_term(self) -> None:
        """Graceful shutdown callback for loop.add_signal_handler().

        Called by the event loop's signal handler with no arguments.
        Sets _is_running to False so the work cycle exits after the
        current iteration completes.
        """
        self.__logger.warning(
            "Received SIGTERM. Shutting down after this work cycle completes."
        )
        self.__is_running = False

    # ------------------------------------------------------------------
    # Async work cycle (Phase 5 — replaces do_work)
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Run the main async work-cycle loop.

        Replaces the synchronous do_work() method.  DB initialisation and
        signal-handler registration are performed by _async_main() before
        this coroutine is awaited.
        """
        self.__logger.info("Starting up.")
        self.__setup_directories()

        config = self.__config
        self.__logger.info("Configuration loaded successfully.")

        nmap_hosts = sorted(set(config.nmap_hosts))
        nessus_hosts = sorted(set(config.nessus_hosts))

        self.__logger.info("nmap hosts: %s", nmap_hosts)
        self.__logger.info("nessus hosts: %s", nessus_hosts)
        self.__logger.info("Jobs per nmap host: %d", config.jobs_per_nmap_host)
        self.__logger.info("Jobs per nessus host: %d", config.jobs_per_nessus_host)
        self.__logger.info("Next scan fetch limit: %d", self.__next_scan_limit)
        self.__logger.info("Poll interval: %d", config.poll_interval)
        self.__logger.info("Test mode: %s", self.__test_mode)
        self.__logger.info("Keep failed jobs: %s", self.__keep_failures)
        self.__logger.info("Keep successful jobs: %s", self.__keep_successes)
        self.__logger.info("Idle shutdown: %s", self.__shutdown_when_idle)
        self.__logger.info('Default owner: "%s"', DEFAULT_OWNER)

        self.__setup_sources()
        self.__setup_sinks()

        # Use asyncio.Queue for the async work cycle.
        self.__successful_job_queue = asyncio.Queue()
        self.__failed_job_queue = asyncio.Queue()

        while self.__is_running:
            try:
                cycle_start = asyncio.get_event_loop().time()

                await self.__check_stop_file_async()
                await self.__check_database_pause_async()
                await db_ops.check_host_next_scans()
                await db_ops.balance_ready_hosts()

                # Dispatch SSH work concurrently across all hosts.
                nmap_tasks = [
                    asyncio.create_task(self.__work_nmap_host(host))
                    for host in nmap_hosts
                    if host not in [h["host"] for h in self.__hosts_on_cooldown]
                ]
                nessus_tasks = [
                    asyncio.create_task(self.__work_nessus_host(host))
                    for host in nessus_hosts
                    if host not in [h["host"] for h in self.__hosts_on_cooldown]
                ]
                await asyncio.gather(*nmap_tasks, *nessus_tasks, return_exceptions=True)

                # Process completed jobs.
                await self.__process_completed_jobs()

                # Check cooldown expirations.
                self.__check_cooldowns(nmap_hosts, nessus_hosts)

                # Check idle shutdown.
                self.__check_all_idle(nmap_hosts, nessus_hosts)

                elapsed = asyncio.get_event_loop().time() - cycle_start
                sleep_time = max(0.0, config.poll_interval - elapsed)
                if sleep_time > 0:
                    self.__logger.debug("Sleeping for %1.1f seconds.", sleep_time)
                    await asyncio.sleep(sleep_time)
                else:
                    self.__logger.debug(
                        "No time to sleep. Last cycle took %1.1f seconds.", elapsed
                    )

            except Exception as e:
                self.__logger.critical(e)
                self.__logger.critical(traceback.format_exc())

        self.__logger.info("Shutting down.")

    async def __check_stop_file_async(self) -> None:
        """Async version of stop file check."""
        if Path(STOP_FILE).exists():
            self.__logger.warning(
                "Stop file found.  Shutting down after this work cycle completes."
            )
            Path(STOP_FILE).unlink()
            self.__is_running = False

    async def __check_database_pause_async(self) -> None:
        """Async version of database pause check."""
        while await db_ops.should_commander_pause() and self.__is_running:
            self.__logger.info("Commander is paused due to database request.")
            await asyncio.sleep(self.__log_output_sleep_duration)
            await self.__check_stop_file_async()

    async def __work_nmap_host(self, host: str) -> None:
        """Perform one work cycle for a single nmap scanner host.

        Retrieves done jobs, then fills the host with new jobs up to the
        configured limit.  SSH/rsync calls are wrapped with asyncio.to_thread()
        to avoid blocking the event loop.
        """
        await self.__done_jobs(host)
        count = await self.__running_job_count(host)
        if count is None:
            return
        counts = {host: count}
        await self.__fill_hosts(
            counts,
            self.__nmap_sources,
            NMAP_WORKGROUP,
            self.__config.jobs_per_nmap_host,
        )

    async def __work_nessus_host(self, host: str) -> None:
        """Perform one work cycle for a single nessus scanner host."""
        await self.__done_jobs(host)
        count = await self.__running_job_count(host)
        if count is None:
            return
        counts = {host: count}
        await self.__fill_hosts(
            counts,
            self.__nessus_sources,
            NESSUS_WORKGROUP,
            self.__config.jobs_per_nessus_host,
        )

    async def __process_completed_jobs(self) -> None:
        """Process all jobs currently in the success and failure queues."""
        tasks = []
        while not self.__successful_job_queue.empty():
            job_path = self.__successful_job_queue.get_nowait()
            tasks.append(
                asyncio.create_task(self.__process_successful_job(job_path))
            )
        while not self.__failed_job_queue.empty():
            job_path = self.__failed_job_queue.get_nowait()
            tasks.append(
                asyncio.create_task(self.__process_failed_job(job_path))
            )
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def __check_cooldowns(self, nmap_hosts: list, nessus_hosts: list) -> None:
        """Check for hosts coming off cooldown and restore them to rotation."""
        cooldown_duration = (
            self.__config.scanner_reliability.cooldown_duration_minutes * 60
        )
        for host_info in self.__hosts_on_cooldown[:]:
            cooldown_end = host_info["cooldown_start"] + cooldown_duration
            if time.time() >= cooldown_end:
                if "nmap" in host_info.get("work_groups", []):
                    nmap_hosts.append(host_info["host"])
                    nmap_hosts.sort()
                if "nessus" in host_info.get("work_groups", []):
                    nessus_hosts.append(host_info["host"])
                    nessus_hosts.sort()
                self.__hosts_on_cooldown.remove(host_info)
                self.__logger.debug(
                    "Host '%s' has been put back into rotation", host_info["host"]
                )
            else:
                self.__logger.debug(
                    "Host '%s' is out of rotation until %s",
                    host_info["host"],
                    time.strftime(
                        "%Y-%m-%dT%H:%M:%S", time.localtime(cooldown_end)
                    ),
                )

    def __check_all_idle(self, nmap_hosts: list, nessus_hosts: list) -> None:
        """Check if all hosts are idle and handle shutdown_when_idle.

        This is a simplified check; tasks 5.2/5.3 will refine with actual
        running-job counts.
        """
        pass


def load_config() -> CommanderConfig:
    """Load and validate commander configuration using cyhy-config.

    Searches for configuration in the following order:
    1. CYHY_CONFIG_PATH environment variable (file path)
    2. CYHY_CONFIG_SSM_PATH environment variable (AWS SSM Parameter Store path)
    3. ./cyhy.toml
    4. ~/.cyhy/cyhy.toml
    5. /etc/cyhy.toml

    Returns:
        CommanderConfig: Validated configuration object.

    Raises:
        Exception: If no configuration file is found or validation fails.
    """
    return get_config(model=CommanderConfig)


async def _async_main(args: argparse.Namespace) -> None:
    """Async entry point: load config, init DB, run commander."""
    workingDir = Path.cwd() / args.working_dir
    if not workingDir.exists():
        print(
            'Working directory "%s" does not exist.  Attempting to create...' % str(workingDir),
            file=sys.stderr,
        )
        workingDir.mkdir()
    os.chdir(str(workingDir))

    config = load_config()
    setup_logging(log_level=config.log_level)
    commander = Commander(config)

    # Initialize database connection.
    await cyhy_db.initialize_db(config.mongodb_uri, config.mongodb_database)
    commander._Commander__logger.info("Database initialized.")

    # Ensure the default owner RequestDoc exists.
    await db_ops.setup_default_owner()

    # Register signal handlers on the running event loop.
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, commander.handle_term)
    loop.add_signal_handler(signal.SIGINT, commander.handle_term)

    await commander.run()


def cli_entry() -> None:
    """Entry point for the cyhy-commander CLI."""
    parser = argparse.ArgumentParser(
        description="CyHy Commander: feeds scanners jobs and processes results."
    )
    parser.add_argument("working_dir", help="Working directory for job files")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "-l", "--stdout-log", action="store_true", help="Log to standard out"
    )
    args = parser.parse_args()
    asyncio.run(_async_main(args))


# Keep backward-compatible entry point name
def main() -> None:
    """Backward-compatible entry point; delegates to cli_entry()."""
    cli_entry()


if __name__ == "__main__":
    main()
