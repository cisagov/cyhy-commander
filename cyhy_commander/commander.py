#!/usr/bin/env python3

"""Cyber Hygiene commander.

Feeds scanners jobs, processes output, and stores results in database.
"""

import argparse
import asyncio
from collections import defaultdict
import logging
import os
import queue
from pathlib import Path, PurePosixPath
import random
import shlex
import shutil
import signal
import sys
import threading
import time
import traceback

import cyhy_db
from cyhy_config import get_config

from .config_model import CommanderConfig
from . import db_ops

# TODO: Phase 6 — replace with cyhy-logging setup_logging
# from cyhy.util import setup_logging  (removed)

# Default owner constant — "ownerless" hosts belong to this org.
# Sourced from db_ops to keep a single definition.
DEFAULT_OWNER = db_ops.DEFAULT_OWNER

# TODO: task 4.2 — replace with cyhy_db.models.enum.Stage
class _StageStub:
    NETSCAN1 = "NETSCAN1"
    NETSCAN2 = "NETSCAN2"
    PORTSCAN = "PORTSCAN"
    VULNSCAN = "VULNSCAN"

STAGE = _StageStub()

# TODO: task 4.2 — replace with cyhy_db.models.enum.ScanType
class _ScanTypeStub:
    CYHY = "CYHY"

SCAN_TYPE = _ScanTypeStub()

# TODO: task 4.2 — replace CHDatabase method calls with db_ops.*
# CHDatabase stub — methods used in do_work() will be replaced in task 4.2
class _CHDatabaseStub:
    def __init__(self, *args, **kwargs):
        pass

    def check_host_next_scans(self):
        pass  # TODO: task 4.2 — replace with db_ops.check_host_next_scans()

    def balance_ready_hosts(self):
        pass  # TODO: task 4.2 — replace with db_ops.balance_ready_hosts()

    def should_commander_pause(self):
        return False  # TODO: task 4.2 — replace with db_ops.should_commander_pause()

CHDatabase = _CHDatabaseStub

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
LOG_FILE = "/var/log/cyhy/commander.log"
LOGGER_FORMAT = "%(asctime)-15s %(levelname)s %(name)s - %(message)s"
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
    def __init__(self, config: CommanderConfig, debug_logging=False, console_logging=False):
        # Set up logging first in order to log any errors as soon as possible.
        self.__logger = logging.getLogger(__name__)
        self.__setup_logging(debug_logging, console_logging)

        self.__all_hosts_idle = False
        self.__config = config
        self.__db = None
        self.__failed_job_queue = None
        self.__failure_sinks = []
        self.__host_exceptions = defaultdict(lambda: 0)
        self.__hosts_on_cooldown = []
        self.__is_processing_jobs = True
        self.__is_running = True
        self.__job_processing_sleep_duration = 1
        self.__keep_failures = config.keep_failures
        self.__keep_successes = config.keep_successes
        self.__log_output_sleep_duration = 10
        self.__nessus_sources = []
        self.__next_scan_limit = config.next_scan_limit
        self.__nmap_sources = []
        self.__queue_monitor_output_lock = threading.Lock()
        self.__setup_directories()
        self.__shutdown_when_idle = config.shutdown_when_idle
        self.__success_sinks = []
        self.__successful_job_queue = None
        self.__test_mode = config.test_mode

        # New SSH transport (Fabric replacement)
        self.__ssh = ssh_transport.SSHTransport(self.__logger)

    def __setup_logging(self, debug_logging, console_logging):
        # get default logging setup
        if debug_logging:
            level = logging.DEBUG
        else:
            level = DEFAULT_LOGGER_LEVEL

        if console_logging:
            # TODO: Phase 6 — replace with cyhy-logging setup_logging(level, console=True)
            logging.basicConfig(level=level, format=LOGGER_FORMAT, stream=sys.stdout)
        else:
            # TODO: Phase 6 — replace with cyhy-logging setup_logging(level, filename=LOG_FILE)
            logging.basicConfig(level=level, format=LOGGER_FORMAT)

        self.__logger.debug("Debug logging enabled")

    def __setup_directories(self):
        for directory in (SUCCESS_DIR, PUSHED_DIR, FAILED_DIR):
            path = Path(directory)
            if not path.exists():
                self.__logger.info('Creating directory "%s".' % (directory))
                path.mkdir(parents=True)


    async def __setup_db(self, uri: str, db_name: str) -> None:
        """Initialize the cyhy-db connection using Beanie/Motor.

        Calls ``cyhy_db.initialize_db`` which creates an AsyncMongoClient,
        selects the named database, and registers all Beanie document models.
        After this call all Beanie document classes are ready for async queries.
        """
        self.__db = await cyhy_db.initialize_db(uri, db_name)
        # TODO: task 4.2 — remove _CHDatabaseStub once all CHDatabase calls
        # are replaced with db_ops.* equivalents.
        self.__ch_db = CHDatabase(next_scan_limit=self.__next_scan_limit)

    def __setup_sources(self):
        if self.__test_mode:
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN1,
                    count=self.__config.job_sizing.netscan1,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN2,
                    count=self.__config.job_sizing.netscan2,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.PORTSCAN,
                    count=self.__config.job_sizing.portscan,
                )
            )
            self.__nessus_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.VULNSCAN,
                    count=self.__config.job_sizing.vulnscan,
                )
            )
        else:
            self.__nessus_sources.append(DirectoryJobSource(DROP_DIR))
            self.__nmap_sources.append(
                DatabaseJobSource(
                    NETSCAN1_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN1,
                    count=self.__config.job_sizing.netscan1,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    NETSCAN2_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN2,
                    count=self.__config.job_sizing.netscan2,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    PORTSCAN_JOB_FILE,
                    self.__db,
                    job_type=STAGE.PORTSCAN,
                    count=self.__config.job_sizing.portscan,
                )
            )
            self.__nessus_sources.append(
                DatabaseJobSource(
                    VULNSCAN_JOB_FILE,
                    self.__db,
                    job_type=STAGE.VULNSCAN,
                    count=self.__config.job_sizing.vulnscan,
                )
            )

    def __setup_sinks(self):
        if self.__test_mode:
            noop_sink = NoOpSink(self.__db)
            self.__success_sinks.append(noop_sink)
        else:
            netscan1_sink = NmapSink(self.__db, STAGE.NETSCAN1)
            netscan2_sink = NmapSink(self.__db, STAGE.NETSCAN2)
            portscan_sink = NmapSink(self.__db, STAGE.PORTSCAN)
            vulnscan_sink = NessusSink(self.__db)
            self.__success_sinks.extend(
                (netscan1_sink, netscan2_sink, portscan_sink, vulnscan_sink)
            )
        self.__failure_sinks = [TryAgainSink(self.__db)]

    def __done_jobs(self, host: str) -> None:
        try:
            cp = self.__ssh.run(host, "ls {d}".format(d=shlex.quote(DONE_DIR)))
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
                cp_done = self.__ssh.run(
                    host,
                    "test -f {p} && cat {p} || true".format(p=shlex.quote(done_path)),
                )
                exit_code = (cp_done.stdout or "").strip()
                if not exit_code:
                    self.__logger.warning("%s is not ready for pickup on %s", job, host)
                    continue

                self.__logger.info("%s is ready for pickup on %s", job, host)

                if exit_code == "0":
                    dest_dir = SUCCESS_DIR
                else:
                    dest_dir = FAILED_DIR
                    self.__logger.warning("%s had a non-zero exit code: %s", job, exit_code)

                local_job_dir = str(Path(dest_dir) / job)
                self.__ssh.rsync_pull_dir(
                    host=host,
                    remote_dir=job_path,
                    local_dir=local_job_dir,
                )

                self.__logger.info(
                    "%s was copied successfully from %s to %s",
                    job,
                    host,
                    dest_dir,
                )

                # remove remote dir
                cp_rm = self.__ssh.run(host, "rm -rf {p}".format(p=shlex.quote(job_path)))
                if cp_rm.returncode == 0:
                    self.__logger.info("%s was removed from %s", job, host)
                else:
                    self.__logger.warning(
                        "Unable to remove %s from %s: %s",
                        job_path,
                        host,
                        (cp_rm.stderr or "").strip(),
                    )

                if dest_dir == SUCCESS_DIR:
                    self.__successful_job_queue.put(local_job_dir)
                else:
                    self.__failed_job_queue.put(local_job_dir)

        except Exception as e:
            self.__logger.error("Exception when retrieving done jobs from %s", host)
            self.__logger.error(e)
            self.__host_exceptions[host] += 1

    def __running_job_count(self, host: str):
        try:
            cp = self.__ssh.run(host, "ls {d}".format(d=shlex.quote(RUNNING_DIR)))
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

    def __push_job(self, host: str, job_path: str) -> None:
        try:
            job_name = Path(job_path.rstrip("/")).name
            remote_job_dir = str(PurePosixPath(RUNNING_DIR) / job_name)

            self.__ssh.rsync_push_dir(
                host=host,
                local_dir=job_path,
                remote_dir=remote_job_dir,
            )

            self.__logger.info("%s was pushed successfully to %s", job_path, host)

            cp_touch = self.__ssh.run(
                host,
                "touch {p}".format(p=shlex.quote(str(PurePosixPath(remote_job_dir) / READY_FILE))),
            )
            if cp_touch.returncode != 0:
                self.__logger.error(
                    "Error touching %s on host %s: %s",
                    os.path.join(remote_job_dir, READY_FILE),
                    host,
                    (cp_touch.stderr or "").strip(),
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

    def __all_idle(self, counts):
        for (host, count) in counts.items():
            if count > 0:
                self.__all_hosts_idle = False
                return False
        if not self.__all_hosts_idle:
            self.__all_hosts_idle = True
            self.__logger.info("All hosts are now idle.")
            if self.__shutdown_when_idle:
                self.__logger.warning("Shutting down since all hosts are idle.")
                self.__is_running = False

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

    def __fill_hosts(self, counts, sources, workgroup_name, jobs_per_host):
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
            self.__push_job(lowest_host, job_path)
            counts[lowest_host] += 1

    def __monitor_job_queues(self):
        # Output the number of jobs that are not done for each queue every
        # self.__log_output_sleep_duration seconds while work is on the queues.
        while self.__is_processing_jobs:
            with self.__queue_monitor_output_lock:
                self.__logger.debug(
                    "%d unfinished jobs in the successful job queue"
                    % self.__successful_job_queue.unfinished_tasks
                )
                self.__logger.debug(
                    "%d unfinished jobs in the failed job queue"
                    % self.__failed_job_queue.unfinished_tasks
                )
            time.sleep(self.__log_output_sleep_duration)

    def __process_queued_jobs(self):

        # define an inner function to process jobs
        def process_job_from_queue(target_job_queue, job_processing_function):
            """Helper function to process jobs from a queue.

            Args:
                target_job_queue (queue.Queue): The queue to get a job to process.
                job_processing_function (callable): The function used to process a job.

            Returns:
                The job path that was processed or None if the queue was empty.
            """
            job_path = None

            # check the successful jobs queue
            try:
                job_path = target_job_queue.get(timeout=1)
            except queue.Empty:
                return job_path

            try:
                job_processing_function(job_path)
            except Exception as e:
                self.__logger.critical(e)
                self.__logger.critical(traceback.format_exc())

            # report task completion no matter what so the queue can be joined
            target_job_queue.task_done()

            # return path of the job that was processed
            return job_path

        # run as long as the commander is processing jobs
        while self.__is_processing_jobs:
            # process successful job
            job_processing_results = process_job_from_queue(
                self.__successful_job_queue, self.__process_successful_job
            )

            # process failed job if a successful job was not processed
            if job_processing_results is None:
                job_processing_results = process_job_from_queue(
                    self.__failed_job_queue, self.__process_failed_job
                )

            # sleep if both queues are empty
            if job_processing_results is None:
                time.sleep(self.__job_processing_sleep_duration)

    def __process_successful_job(self, job_path):
        # Get the name of the current thread
        thread_name = threading.current_thread().name

        for sink in self.__success_sinks:
            if sink.can_handle(job_path):
                self.__logger.info(
                    "[%s] Processing %s with %s" % (thread_name, job_path, sink)
                )
                sink.handle(job_path)
                self.__logger.info("[%s] Processing completed" % thread_name)
                if not self.__test_mode and not self.__keep_successes:
                    shutil.rmtree(job_path)
                    self.__logger.info("[%s] %s deleted" % (thread_name, job_path))
                return
        self.__logger.warning(
            "[%s] No handler was able to process %s" % (thread_name, job_path)
        )

    def __process_failed_job(self, job_path):
        # Get the name of the current thread
        thread_name = threading.current_thread().name

        for sink in self.__failure_sinks:
            if sink.can_handle(job_path):
                self.__logger.warning(
                    "[%s] Processing %s with %s" % (thread_name, job_path, sink)
                )
                sink.handle(job_path)
                self.__logger.info("[%s] Processing completed" % thread_name)
                if not self.__test_mode and not self.__keep_failures:
                    shutil.rmtree(job_path)
                    self.__logger.info("[%s] %s deleted" % (thread_name, job_path))
                return
        self.__logger.warning(
            "[%s] No handler was able to process %s" % (thread_name, job_path)
        )

    def handle_term(self, signal, frame):
        self.__logger.warning(
            "Received signal %d.  Shutting down after this work cycle completes."
            % signal
        )
        self.__is_running = False

    def __check_stop_file(self):
        if Path(STOP_FILE).exists():
            self.__logger.warning(
                "Stop file found.  Shutting down after this work cycle completes."
            )
            Path(STOP_FILE).unlink()
            self.__is_running = False

    def __check_database_pause(self):
        while self.__ch_db.should_commander_pause() and self.__is_running:
            self.__logger.info("Commander is paused due to database request.")
            time.sleep(self.__log_output_sleep_duration)
            self.__check_stop_file()

    async def __setup_default_owner(self, scheduler: str) -> None:
        """Ensure a RequestDoc exists in the database for the default owner.

        Delegates to ``db_ops.setup_default_owner`` which creates a RequestDoc
        with default values if one does not already exist.

        Args:
            scheduler: The scheduler value to assign to the default owner's
                RequestDoc (e.g. ``"PERSISTENT1"``).
        """
        await db_ops.setup_default_owner(scheduler)

    def do_work(self):
        self.__logger.info("Starting up.")
        self.__setup_directories()

        config = self.__config
        self.__logger.info("Configuration loaded successfully.")

        # Use config fields directly from the Pydantic model
        nmap_hosts = sorted(set(config.nmap_hosts))
        nessus_hosts = sorted(set(config.nessus_hosts))

        self.__logger.info("nmap hosts: %s" % nmap_hosts)
        self.__logger.info("nessus hosts: %s" % nessus_hosts)
        jobs_per_nmap_host = config.jobs_per_nmap_host
        self.__logger.info("Jobs per nmap host: %d", jobs_per_nmap_host)
        jobs_per_nessus_host = config.jobs_per_nessus_host
        self.__logger.info("Jobs per nessus host: %d", jobs_per_nessus_host)
        self.__logger.info("Next scan fetch limit: %d", self.__next_scan_limit)
        self.__logger.info("Poll interval: %d", self.__config.poll_interval)
        asyncio.run(self.__setup_db(config.mongodb_uri, config.mongodb_database))
        self.__logger.info("Database: %s", self.__db)
        self.__logger.info("Test mode: %s", self.__test_mode)
        self.__logger.info("Keep failed jobs: %s", self.__keep_failures)
        job_processing_thread_count = 4
        self.__logger.info(
            "Number of job processing threads: %d", job_processing_thread_count
        )
        self.__logger.info("Keep successful jobs: %s", self.__keep_successes)
        self.__logger.info("Idle shutdown: %s", self.__shutdown_when_idle)
        self.__logger.info('Default owner: "%s"' % DEFAULT_OWNER)
        default_scheduler = "PERSISTENT1"
        self.__logger.info('Default scheduler: "%s"' % default_scheduler)
        asyncio.run(self.__setup_default_owner(default_scheduler))
        self.__setup_sources()
        self.__setup_sinks()

        self.__successful_job_queue = queue.Queue()
        self.__failed_job_queue = queue.Queue()

        # spin up the thread pool to process retrieved work
        job_processing_threads = []
        for t in range(job_processing_thread_count):
            job_processing_thread = threading.Thread(
                name="JobProcessor-%d" % t, target=self.__process_queued_jobs
            )
            job_processing_threads.append(job_processing_thread)
            try:
                job_processing_thread.start()
            except Exception as e:
                self.__logger.error("Unable to start job processing thread #%s", t)
                self.__logger.error(e)
                # bail out
                self.__logger.critical(
                    "Shutting down due to inability to start job processing threads."
                )
                self.__is_running = False

        # spin up a thread to output queue load information
        self.__queue_monitor_output_lock.acquire()
        job_queue_monitor_thread = threading.Thread(
            name="QueueMonitor", target=self.__monitor_job_queues
        )
        try:
            job_queue_monitor_thread.start()
        except Exception as e:
            self.__logger.error("Unable to start job queue monitoring thread")
            self.__logger.error(e)
            # bail out
            self.__logger.critical(
                "Shutting down due to inability to start queue monitoring thread."
            )
            self.__is_running = False

        # pairs of hosts and job sources
        work_groups = (
            (NMAP_WORKGROUP, nmap_hosts, self.__nmap_sources, jobs_per_nmap_host),
            (
                NESSUS_WORKGROUP,
                nessus_hosts,
                self.__nessus_sources,
                jobs_per_nessus_host,
            ),
        )

        # main work loop
        while self.__is_running:
            try:
                # record time at start of duty cycle
                cycle_start_time = time.time()
                next_cycle_start_time = cycle_start_time + self.__config.poll_interval

                # check for hosts that are coming off of cooldown
                self.__logger.debug("Checking for hosts to bring off of cooldown")
                cooldown_duration = self.__config.scanner_reliability.cooldown_duration_minutes * 60
                for host_info in self.__hosts_on_cooldown[:]:
                    cooldown_end = host_info["cooldown_start"] + cooldown_duration
                    if time.time() >= cooldown_end:
                        for group in host_info["work_groups"]:
                            work_groups[group][1].append(host_info["host"])
                            work_groups[group][1].sort()
                        self.__hosts_on_cooldown.remove(host_info)
                        self.__logger.debug(
                            "Host '%s' has been put back into rotation" % host_info["host"]
                        )
                    else:
                        self.__logger.debug(
                            "Host '%s' is out of rotation until %s"
                            % (
                                host_info["host"],
                                time.strftime(
                                    "%Y-%m-%dT%H:%M:%S", time.localtime(cooldown_end)
                                ),
                            )
                        )

                # check for hosts that have had multiple exceptions
                self.__logger.debug("Checking for hosts with too many exceptions")
                exceptions_before_cooldown = self.__config.scanner_reliability.exceptions_before_cooldown
                for (host, count) in self.__host_exceptions.items():
                    if count > exceptions_before_cooldown:
                        groups = []
                        for (index, group) in enumerate(work_groups):
                            if host in group[1]:
                                groups.append(index)
                                group[1].remove(host)

                        info_dict = {
                            "host": host,
                            "cooldown_start": time.time(),
                            "work_groups": groups,
                        }
                        self.__host_exceptions[host] = 0
                        self.__hosts_on_cooldown.append(info_dict)
                        self.__logger.debug(
                            "Host '%s' has been removed from rotation" % host
                        )

                # process anything that has completed
                self.__logger.debug(
                    "Checking remotes for completed jobs to download and process"
                )
                self.__queue_monitor_output_lock.release()
                for (workgroup_name, hosts, sources, jobs_per_host) in work_groups:
                    if hosts == None:
                        continue
                    for host in hosts:
                        self.__done_jobs(host)

                # wait for work to process
                self.__logger.debug("Waiting for completed jobs to be processed.")
                self.__successful_job_queue.join()
                self.__failed_job_queue.join()
                self.__queue_monitor_output_lock.acquire()

                # check for scheduled hosts
                self.__logger.debug(
                    "Checking for scheduled DONE hosts to mark WAITING."
                )
                self.__ch_db.check_host_next_scans()

                # balance the number of hosts that are ready and running
                self.__logger.debug("Balancing READY status of hosts.")
                self.__ch_db.balance_ready_hosts()

                # push out new work and count
                self.__logger.debug("Checking sources for new jobs")
                all_workgroup_counts = {}
                for (workgroup_name, hosts, sources, jobs_per_host) in work_groups:
                    if hosts == None:
                        continue
                    counts = {}
                    for host in hosts:
                        counts[host] = self.__running_job_count(host)
                    self.__fill_hosts(counts, sources, workgroup_name, jobs_per_host)
                    all_workgroup_counts.update(counts)

                # check to see if all host are idle and log it
                self.__all_idle(all_workgroup_counts)
                self.__check_stop_file()
                if self.__is_running:
                    now = time.time()
                    if now < next_cycle_start_time:
                        sleep_time = next_cycle_start_time - now
                        self.__logger.debug(
                            "Sleeping for %1.1f seconds.\n\n\n" % sleep_time
                        )
                        time.sleep(sleep_time)
                    else:
                        self.__logger.debug(
                            "No time to sleep.  Last cycle took %1.1f seconds.\n\n\n"
                            % (now - cycle_start_time)
                        )
                self.__check_stop_file()
                self.__check_database_pause()
            except Exception as e:
                self.__logger.critical(e)
                self.__logger.critical(traceback.format_exc())

        # signal job processing threads to exit once they have finished all
        # queued work
        self.__is_processing_jobs = False
        self.__queue_monitor_output_lock.release()

        # wait for the job processing threads to exit
        for job_processing_thread in job_processing_threads:
            job_processing_thread.join()

        # wait for the job queue monitoring thread to exit
        job_queue_monitor_thread.join()

        self.__logger.info("Shutting down.")


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
    # TODO: Phase 5 — call asyncio.run(main(args))

    workingDir = Path.cwd() / args.working_dir
    if not workingDir.exists():
        print(
            'Working directory "%s" does not exist.  Attempting to create...' % str(workingDir),
            file=sys.stderr,
        )
        workingDir.mkdir()
    os.chdir(str(workingDir))

    config = load_config()
    commander = Commander(config, args.debug, args.stdout_log)

    signal.signal(signal.SIGTERM, commander.handle_term)
    signal.signal(signal.SIGINT, commander.handle_term)
    commander.do_work()


# Keep backward-compatible entry point name
def main():
    """Backward-compatible entry point; delegates to cli_entry()."""
    cli_entry()


if __name__ == "__main__":
    main()
