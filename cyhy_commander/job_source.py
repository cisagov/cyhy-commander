import os
import shutil
import tempfile

from cyhy.core import *
from cyhy.db import CHDatabase
from cyhy import util

JOB_FILENAME = "job"
PORTS_FILE_NAME = "ports"


class JobSource(object):
    def __init__(self):
        pass

    def get_job(self):
        return False


class DirectoryJobSource(JobSource):
    def __init__(self, directory):
        self.__directory = directory
        if not os.path.exists(directory):
            os.makedirs(directory)

    def __str__(self):
        return "<DirectoryJobSource %s>" % (self.__directory)

    def get_job(self):
        return self.__get_queued_job()

    def __get_queued_job(self):
        jobs = os.listdir(self.__directory)
        if len(jobs) == 0:
            return None
        job = jobs.pop()
        job_path = os.path.join(self.__directory, job)
        return job_path


class DatabaseJobSource(JobSource):
    def __init__(self, job_file, db, job_type=STAGE.NETSCAN1, count=32):
        self.__job_file = job_file
        self.__db = db
        self.__ch_db = CHDatabase(db)
        self.__job_type = job_type
        self.__count = count
        self.__temp_dir = tempfile.mkdtemp()

    def __str__(self):
        return "<DatabaseJobSource %s %s>" % (self.__job_type, self.__db)

    def __del__(self):
        shutil.rmtree(self.__temp_dir)

    def get_job(self):
        return self.__make_job()

    def __make_job(self):
        # quick check
        if not self.__db.HostDoc.exists(self.__job_type, STATUS.READY):
            return None

        # actual attempt to claim hosts
        hosts = self.__ch_db.fetch_ready_hosts(
            count=self.__count, stage=self.__job_type
        )
        if len(hosts) == 0:
            return None

        # create the job directory
        date = util.utcnow().isoformat().replace(":", "").replace("-", "")
        dir_name = "%s-%s" % (self.__job_type, date)
        job_path = os.path.join(self.__temp_dir, dir_name)
        os.mkdir(job_path)

        # copy in job file
        job_file_path = os.path.join(job_path, JOB_FILENAME)
        shutil.copyfile(self.__job_file, job_file_path)

        # create the target list
        target_file_name = "%s.txt" % dir_name
        target_path = os.path.join(job_path, target_file_name)
        target_file = open(target_path, "w")

        for host in hosts:
            print >> target_file, host["ip"]
        target_file.close()

        # vulnerability scans require a port list file
        if self.__job_type == STAGE.VULNSCAN:
            ports = self.__ch_db.get_open_ports(ips)
            ports_string = util.list_to_range_string(ports)
            ports_path = os.path.join(job_path, PORTS_FILE_NAME)
            ports_file = open(ports_path, "w")
            print >> ports_file, ports_string
            ports_file.close()

        # return path to the job
        return job_path
