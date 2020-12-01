#!/usr/bin/env python

"""Cyber Hygiene commander.
Feeds scanners jobs, processes output, and stores results in database.

Usage:
  commander [options] <working-dir>
  commander (-h | --help)
  commander --version

Options:
  -b --background                Run in background (daemonize).
  -d --debug                     Enable debug logging.
  -l --stdout-log                Log to standard out.
  -s SECTION --section=SECTION   Configuration section to use.

"""


# easy-installs
# fabric
# python-daemon

import os
import sys
import shutil
import time
import lockfile
import random
import signal
import traceback
from ConfigParser import SafeConfigParser
import logging

from fabric.network import disconnect_all
from fabric.tasks import Task, execute
from fabric.api import task, run, env
from fabric import operations
import daemon
from docopt import docopt

from cyhy.db import CHDatabase
from cyhy.core import *
from job_source import DirectoryJobSource, DatabaseJobSource
from job_sink import NmapSink, NessusSink, TryAgainSink, NoOpSink
from cyhy.db import database
from cyhy.util import setup_logging

# fabric configuration
env.use_ssh_config = True
env.keepalive = 30
env.command_timeout = 60

# remote files
RUNNING_DIR = "runner/running"
DONE_DIR = "runner/done"
READY_FILE = ".ready"
DONE_FILE = ".done"

# local files
PUSHED_DIR = "pushed"
SUCCESS_DIR = "done"
FAILED_DIR = "failed"
DROP_DIR = "drop"
LOG_FILE = "/var/log/cyhy/commander.log"
CONFIG_FILENAME = "/etc/cyhy/commander.conf"
STOP_FILE = "stop"
LOGGER_FORMAT = "%(asctime)-15s %(levelname)s %(name)s - %(message)s"
DEFAULT_LOGGER_LEVEL = logging.INFO
LOCK_FILENAME = "cyhy-commander"

# local job files
me = os.path.realpath(__file__)
myDir = os.path.dirname(me)
jobsDir = os.path.join(myDir, "jobs")
NETSCAN1_JOB_FILE = os.path.join(jobsDir, "netscan1.sh")
NETSCAN2_JOB_FILE = os.path.join(jobsDir, "netscan2.sh")
PORTSCAN_JOB_FILE = os.path.join(jobsDir, "portscan.sh")
VULNSCAN_JOB_FILE = os.path.join(jobsDir, "nessus6.py")
BASESCAN_JOB_FILE = os.path.join(jobsDir, "basescan.sh")
SLEEP_JOB_FILE = os.path.join(jobsDir, "rand-sleep.py")

# config file
DEFAULT = "DEFAULT"
PRODUCTION_SECTION = "production"
TESTING_SECTION = "testing"
TESTING_PURGE_SECTION = "testing-purge"
NMAP_HOSTS = "nmap-hosts"
NESSUS_HOSTS = "nessus-hosts"
JOBS_PER_NMAP_HOST = "jobs-per-nmap-host"
JOBS_PER_NESSUS_HOST = "jobs-per-nessus-host"
POLL_INTERVAL = "poll-interval"
DATABASE_NAME = "database-name"
DATABASE_URI = "database-uri"
DEFAULT_SECTION = "default-section"
TEST_MODE = "test-mode"
KEEP_FAILURES = "keep-failures"
KEEP_SUCCESSES = "keep-successes"
SHUTDOWN_WHEN_IDLE = "shutdown-when-idle"
NEXT_SCAN_LIMIT = "next-scan-limit"

# TODO eventual config options
IPS_PER_NETSCAN1_JOB = 128
IPS_PER_NETSCAN2_JOB = 128 / 2
IPS_PER_PORTSCAN_JOB = 32 / 4
IPS_PER_VULNSCAN_JOB = 4
IPS_PER_BASESCAN_JOB = 32
RANDOMIZE_SOURCES = True

NMAP_WORKGROUP = "nmap"
NESSUS_WORKGROUP = "nessus"


class Commander(object):
    def __init__(self, config_section=None, debug_logging=False, console_logging=False):
        self.__logger = logging.getLogger(__name__)
        self.__config_section = config_section
        self.__is_running = True
        self.__all_hosts_idle = False
        self.__next_scan_limit = 2000
        self.__setup_logging(debug_logging, console_logging)
        self.__setup_directories()
        self.__nmap_sources = []
        self.__nessus_sources = []
        self.__success_sinks = []
        self.__failure_sinks = []
        self.__db = None
        self.__test_mode = False
        self.__keep_failures = False
        self.__keep_successes = False
        self.__shutdown_when_idle = False

    def __setup_logging(self, debug_logging, console_logging):
        # get default logging setup
        if debug_logging:
            level = logging.DEBUG
        else:
            level = DEFAULT_LOGGER_LEVEL

        if console_logging:
            setup_logging(level, console=True)
        else:
            setup_logging(level, filename=LOG_FILE)

        # This is only output if debug in enabled.  Skipped outwise.
        self.__logger.debug("Debug logging enabled")

    def __setup_directories(self):
        for directory in (SUCCESS_DIR, PUSHED_DIR, FAILED_DIR):
            if not os.path.exists(directory):
                self.__logger.info('Creating directory "%s".' % (directory))
                os.makedirs(directory)

    def __setup_db(self, db_name, uri):
        self.__db = database.db_from_connection(uri, db_name)
        self.__ch_db = CHDatabase(self.__db, next_scan_limit=self.__next_scan_limit)

    def __setup_sources(self):
        if self.__test_mode:
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN1,
                    count=IPS_PER_NETSCAN1_JOB,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN2,
                    count=IPS_PER_NETSCAN2_JOB,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.PORTSCAN,
                    count=IPS_PER_PORTSCAN_JOB,
                )
            )
            self.__nessus_sources.append(
                DatabaseJobSource(
                    SLEEP_JOB_FILE,
                    self.__db,
                    job_type=STAGE.VULNSCAN,
                    count=IPS_PER_VULNSCAN_JOB,
                )
            )
            # self.__nmap_sources.append(DatabaseJobSource(SLEEP_JOB_FILE, self.__db, job_type=STAGE.BASESCAN, count=IPS_PER_BASESCAN_JOB))
        else:
            self.__nessus_sources.append(DirectoryJobSource(DROP_DIR))
            self.__nmap_sources.append(
                DatabaseJobSource(
                    NETSCAN1_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN1,
                    count=IPS_PER_NETSCAN1_JOB,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    NETSCAN2_JOB_FILE,
                    self.__db,
                    job_type=STAGE.NETSCAN2,
                    count=IPS_PER_NETSCAN2_JOB,
                )
            )
            self.__nmap_sources.append(
                DatabaseJobSource(
                    PORTSCAN_JOB_FILE,
                    self.__db,
                    job_type=STAGE.PORTSCAN,
                    count=IPS_PER_PORTSCAN_JOB,
                )
            )
            self.__nessus_sources.append(
                DatabaseJobSource(
                    VULNSCAN_JOB_FILE,
                    self.__db,
                    job_type=STAGE.VULNSCAN,
                    count=IPS_PER_VULNSCAN_JOB,
                )
            )
            # self.__nmap_sources.append(DatabaseJobSource(BASESCAN_JOB_FILE, self.__db, job_type=STAGE.BASESCAN, count=IPS_PER_BASESCAN_JOB))

    def __setup_sinks(self):
        if self.__test_mode:
            noop_sink = NoOpSink(self.__db)
            self.__success_sinks.append(noop_sink)
        else:
            netscan1_sink = NmapSink(self.__db, STAGE.NETSCAN1)
            netscan2_sink = NmapSink(self.__db, STAGE.NETSCAN2)
            portscan_sink = NmapSink(self.__db, STAGE.PORTSCAN)
            vulnscan_sink = NessusSink(self.__db)
            # baseline_sink = NmapSink(self.__db, STAGE.BASESCAN)
            self.__success_sinks.extend(
                (netscan1_sink, netscan2_sink, portscan_sink, vulnscan_sink)
            )
        self.__failure_sinks = [TryAgainSink(self.__db)]

    @task
    def __done_jobs(self):
        try:
            output = run("ls %s" % DONE_DIR)
            if output.failed:
                self.__logger.warning(
                    'Unable to get listing of "%s" on %s' % (DONE_DIR, env.host_string)
                )
                output = ""
            doneJobs = output.split()
            for job in doneJobs:
                jobPath = os.path.join(DONE_DIR, job)
                output = run("ls -a %s" % (jobPath))
                jobContents = output.split()
                if DONE_FILE in jobContents:
                    self.__logger.info(
                        "%s is ready for pickup on %s" % (job, env.host_string)
                    )
                    donePath = os.path.join(jobPath, DONE_FILE)
                    exitCode = run("cat %s" % donePath)
                    if exitCode == "0":
                        destDir = SUCCESS_DIR
                    else:
                        destDir = FAILED_DIR
                        self.__logger.warning(
                            "%s had a non-zero exit code: %s" % (job, exitCode)
                        )

                    paths = operations.get(jobPath, destDir)
                    if len(paths.failed) == 0:
                        self.__logger.info(
                            "%s was copied successfully from %s to %s"
                            % (job, env.host_string, destDir)
                        )
                        # remove remote dir
                        run("rm -rf %s" % jobPath)
                        self.__logger.info(
                            "%s was removed from %s" % (job, env.host_string)
                        )
                    local_job_path = os.path.join(destDir, job)

                    if destDir == SUCCESS_DIR:
                        self.__process_successful_job(local_job_path)
                    else:
                        self.__process_failed_job(local_job_path)

                else:
                    self.__logger.warning(
                        "%s is not ready for pickup on %s" % (job, env.host_string)
                    )
        except Exception as e:
            self.__logger.error(
                "Exception when retrieving done jobs from %s" % env.host_string
            )
            self.__logger.error(e)

    @task
    def __running_job_count(self):
        try:
            output = run("ls %s" % RUNNING_DIR)
            if output.failed:
                self.__logger.warning(
                    'Unable to get listing of "%s" on %s'
                    % (RUNNING_DIR, env.host_string)
                )
                return None
            runningJobs = output.split()
            count = len(runningJobs)
            return count
        except Exception as e:
            self.__logger.error(
                "Exception when retrieving running job count from %s" % env.host_string
            )
            self.__logger.error(e)

    @task
    def __push_job(self, job_path):
        try:
            paths = operations.put(job_path, RUNNING_DIR)
            if len(paths.failed) == 0:
                self.__logger.info(
                    "%s was pushed successfully to %s" % (job_path, env.host_string)
                )
                job_name = os.path.basename(job_path)
                run("touch %s" % os.path.join(RUNNING_DIR, job_name, READY_FILE))
                self.__move_to_pushed(job_path)
            else:
                self.__logger.error(
                    "Error pushing %s to host %s" % (job_path, env.host_string)
                )
        except Exception as e:
            self.__logger.error(
                "Exception when pushing %s to host %s" % (job_path, env.host_sring)
            )
            self.__logger.error(e)

    def __unique_filename(self, path):
        if not os.path.exists(path):
            return path
        new_name = "%s.%d" % (os.path.basename(path), int(time.time() * 1000000))
        new_path = os.path.join(os.path.dirname(path), new_name)
        return new_path

    def __move_to_pushed(self, job_path):
        if not self.__test_mode:
            shutil.rmtree(job_path)
            self.__logger.info("%s deleted" % job_path)
        else:
            dest = os.path.join(PUSHED_DIR, os.path.basename(job_path))
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
            execute(self.__push_job, self, job_path, hosts=[lowest_host])
            counts[lowest_host] += 1

    def __process_successful_job(self, job_path):
        for sink in self.__success_sinks:
            if sink.can_handle(job_path):
                self.__logger.info("Processing %s with %s" % (job_path, sink))
                sink.handle(job_path)
                self.__logger.info("Processing completed")
                if not self.__test_mode and not self.__keep_successes:
                    shutil.rmtree(job_path)
                    self.__logger.info("%s deleted" % job_path)
                return
        self.__logger.warning("No handler was able to process %s" % job_path)

    def __process_failed_job(self, job_path):
        for sink in self.__failure_sinks:
            if sink.can_handle(job_path):
                self.__logger.warning("Processing %s with %s" % (job_path, sink))
                sink.handle(job_path)
                self.__logger.info("Processing completed")
                if not self.__test_mode and not self.__keep_failures:
                    shutil.rmtree(job_path)
                    self.__logger.info("%s deleted" % job_path)
                return
        self.__logger.warning("No handler was able to process %s" % job_path)

    def handle_term(self, signal, frame):
        self.__logger.warning(
            "Received signal %d.  Shutting down after this work cycle completes."
            % signal
        )
        self.__is_running = False

    def __check_stop_file(self):
        if os.path.exists(STOP_FILE):
            self.__logger.warning(
                "Stop file found.  Shutting down after this work cycle completes."
            )
            os.remove(STOP_FILE)
            self.__is_running = False

    def __check_database_pause(self):
        while self.__ch_db.should_commander_pause() and self.__is_running:
            self.__logger.info("Commander is paused due to database request.")
            time.sleep(10)
            self.__check_stop_file()

    def __write_config(self):
        config = SafeConfigParser()
        config.set(None, DATABASE_URI, "mongodb://localhost:27017/")
        config.set(None, JOBS_PER_NMAP_HOST, "8")
        config.set(None, JOBS_PER_NESSUS_HOST, "8")
        config.set(None, POLL_INTERVAL, "30")
        config.set(None, NEXT_SCAN_LIMIT, "2000")
        config.set(None, DEFAULT_SECTION, TESTING_SECTION)
        config.set(None, TEST_MODE, "false")
        config.set(None, KEEP_FAILURES, "false")
        config.set(None, SHUTDOWN_WHEN_IDLE, "false")
        config.add_section(TESTING_SECTION)
        config.set(TESTING_SECTION, NMAP_HOSTS, "comma,separated,list")
        config.set(TESTING_SECTION, NESSUS_HOSTS, "comma,separated,list")
        config.set(TESTING_SECTION, DATABASE_NAME, "test_database")
        config.set(TESTING_SECTION, TEST_MODE, "true")
        config.add_section(TESTING_PURGE_SECTION)
        config.set(TESTING_PURGE_SECTION, JOBS_PER_NMAP_HOST, "0")
        config.set(TESTING_PURGE_SECTION, JOBS_PER_NESSUS_HOST, "0")
        config.set(TESTING_PURGE_SECTION, SHUTDOWN_WHEN_IDLE, "true")
        config.set(TESTING_PURGE_SECTION, NMAP_HOSTS, "comma,separated,list")
        config.set(TESTING_PURGE_SECTION, NESSUS_HOSTS, "comma,separated,list")
        config.set(TESTING_PURGE_SECTION, DATABASE_NAME, "test_database")
        config.set(TESTING_PURGE_SECTION, TEST_MODE, "true")
        config.add_section(PRODUCTION_SECTION)
        config.set(PRODUCTION_SECTION, NMAP_HOSTS, "comma,separated,list")
        config.set(PRODUCTION_SECTION, NESSUS_HOSTS, "comma,separated,list")
        config.set(PRODUCTION_SECTION, DATABASE_NAME, "test_database")
        with open(CONFIG_FILENAME, "wb") as config_file:
            config.write(config_file)

    def __read_config(self):
        config = SafeConfigParser()
        config.read([CONFIG_FILENAME])
        return config

    def do_work(self):
        env.warn_only = True
        self.__logger.info("Starting up.")
        self.__setup_directories()

        # process configuration
        if not os.path.exists(CONFIG_FILENAME):
            print >> sys.stderr, 'Configuration file not found: "%s"' % CONFIG_FILENAME
            self.__write_config()
            print >> sys.stderr, "A default configuration file was created in the working directory."
            print >> sys.stderr, "Please edit and relaunch."
            self.__logger.error("Configuration file not found. Exiting.")
            sys.exit(-1)

        config = self.__read_config()
        if self.__config_section == None:
            config_section = config.get(DEFAULT, DEFAULT_SECTION)
        else:
            config_section = self.__config_section
        self.__logger.info('Reading configuration section: "%s"' % config_section)
        nmap_hosts = config.get(config_section, NMAP_HOSTS).split(",")
        nessus_hosts = config.get(config_section, NESSUS_HOSTS).split(",")
        # clean up empty lists from config
        if nmap_hosts == [""]:
            nmap_hosts = None
        if nessus_hosts == [""]:
            nessus_hosts = None
        self.__logger.info("nmap hosts: %s" % nmap_hosts)
        self.__logger.info("nessus hosts: %s" % nessus_hosts)
        jobs_per_nmap_host = config.getint(config_section, JOBS_PER_NMAP_HOST)
        self.__logger.info("Jobs per nmap host: %d", jobs_per_nmap_host)
        jobs_per_nessus_host = config.getint(config_section, JOBS_PER_NESSUS_HOST)
        self.__logger.info("Jobs per nessus host: %d", jobs_per_nessus_host)
        self.__next_scan_limit = config.getint(config_section, NEXT_SCAN_LIMIT)
        self.__logger.info("Next scan fetch limit: %d", self.__next_scan_limit)
        self.__poll_interval = config.getint(config_section, POLL_INTERVAL)
        self.__logger.info("Poll interval: %d", self.__poll_interval)
        db_name = config.get(config_section, DATABASE_NAME)
        db_uri = config.get(config_section, DATABASE_URI)
        self.__setup_db(db_name, db_uri)
        self.__logger.info("Database: %s", self.__db)
        self.__test_mode = config.getboolean(config_section, TEST_MODE)
        self.__logger.info("Test mode: %s", self.__test_mode)
        self.__keep_failures = config.getboolean(config_section, KEEP_FAILURES)
        self.__logger.info("Keep failed jobs: %s", self.__keep_failures)
        self.__keep_successes = config.getboolean(config_section, KEEP_SUCCESSES)
        self.__logger.info("Keep successful jobs: %s", self.__keep_successes)
        self.__shutdown_when_idle = config.getboolean(
            config_section, SHUTDOWN_WHEN_IDLE
        )
        self.__logger.info("Idle shutdown: %s", self.__shutdown_when_idle)
        self.__setup_sources()
        self.__setup_sinks()

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
                next_cycle_start_time = cycle_start_time + self.__poll_interval
                # process anything that has completed
                self.__logger.debug(
                    "Checking remotes for completed jobs to download and process"
                )
                for (workgroup_name, hosts, sources, jobs_per_host) in work_groups:
                    if hosts == None:
                        continue
                    execute(self.__done_jobs, self, hosts=hosts)

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
                all_workgroup_counts = {}  # track counts from each work_group
                for (workgroup_name, hosts, sources, jobs_per_host) in work_groups:
                    if hosts == None:
                        continue
                    counts = execute(self.__running_job_count, self, hosts=hosts)
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
            except Exception, e:
                self.__logger.critical(e)
                self.__logger.critical(traceback.format_exc())
        self.__logger.info("Shutting down.")
        disconnect_all()


def main():
    args = docopt(__doc__, version="v0.0.1")
    workingDir = os.path.join(os.getcwd(), args["<working-dir>"])
    if not os.path.exists(workingDir):
        print >> sys.stderr, 'Working directory "%s" does not exist.  Attempting to create...' % workingDir
        os.mkdir(workingDir)
    os.chdir(workingDir)
    lock = lockfile.LockFile(os.path.join(workingDir, LOCK_FILENAME), timeout=0)
    if lock.is_locked():
        print >> sys.stderr, "Cannot start.  There is already a cyhy-commander executing in this working directory."
        sys.exit(-1)

    commander = Commander(args["--section"], args["--debug"], args["--stdout-log"])

    if args["--background"]:
        context = daemon.DaemonContext(
            working_directory=workingDir, umask=0002, pidfile=lock
        )
        context.signal_map = {
            signal.SIGTERM: commander.handle_term,
            signal.SIGCHLD: signal.SIG_IGN,
        }
        with context:
            commander.do_work()
    else:
        signal.signal(signal.SIGTERM, commander.handle_term)
        signal.signal(signal.SIGINT, commander.handle_term)
        commander.do_work()


if __name__ == "__main__":
    main()
