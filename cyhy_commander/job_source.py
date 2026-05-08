import os
import shutil
import tempfile

# TODO: Replace with cyhy-db enums in Phase 4 (task 4.3)
# from cyhy.core import *
# from cyhy.db import CHDatabase
# from cyhy import util

# TODO stubs for removed cyhy-core symbols
class _STAGEStub:
    NETSCAN1 = "NETSCAN1"
    NETSCAN2 = "NETSCAN2"
    PORTSCAN = "PORTSCAN"
    VULNSCAN = "VULNSCAN"

STAGE = _STAGEStub()

class _STATUSStub:
    READY = "READY"

STATUS = _STATUSStub()

class _CHDatabaseStub:
    def __init__(self, db):
        self._db = db

    def fetch_ready_hosts(self, count, stage):
        # TODO: Replace with db_ops.fetch_ready_hosts in Phase 4 (task 4.3)
        raise NotImplementedError("CHDatabase.fetch_ready_hosts not yet migrated")

CHDatabase = _CHDatabaseStub

class _UtilStub:
    @staticmethod
    def utcnow():
        # TODO: Replace with datetime.datetime.utcnow() or equivalent in Phase 4
        import datetime
        return datetime.datetime.utcnow()

    @staticmethod
    def list_to_range_string(ports):
        # TODO: Replace with real implementation in Phase 4 (task 4.3)
        raise NotImplementedError("util.list_to_range_string not yet migrated")

util = _UtilStub()

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
        if not hosts:
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

        # vulnerability scans may include hostnames
        if self.__job_type == STAGE.VULNSCAN:
            for host in hosts:
                # include all hostnames if present, otherwise use IP alone
                if host.get("hostnames"):
                    for h in host["hostnames"]:
                        print("%s[%s]" % (h["hostname"], host["ip"]), file=target_file)
                else:
                    print(host["ip"], file=target_file)
        else:
            for host in hosts:
                print(host["ip"], file=target_file)

        target_file.close()

        # vulnerability scans require a port list file
        if self.__job_type == STAGE.VULNSCAN:
            ips = [host["ip"] for host in hosts]
            ports = self.__ch_db.get_open_ports(ips)
            ports_string = util.list_to_range_string(ports)
            ports_path = os.path.join(job_path, PORTS_FILE_NAME)
            ports_file = open(ports_path, "w")
            print(ports_string, file=ports_file)
            ports_file.close()

        # return path to the job
        return job_path
