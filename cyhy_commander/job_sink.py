import os
import glob
import random
from cyhy.core import *
from cyhy.db import CHDatabase
from cyhy_commander.nmap import NmapImporter
from cyhy_commander.nessus import NessusImporter

import netaddr

OUTPUT_FILENAME = "job.out"
TARGETS_GLOB = "*SCAN*.txt"


class NmapSink(object):
    def __init__(self, db, stage):
        self.__db = db
        self.__stage = stage

    def __str__(self):
        return "<NmapSink %s %s>" % (self.__stage, self.__db)

    def can_handle(self, job_path):
        job_name = os.path.basename(job_path)
        return job_name.startswith(self.__stage)

    def handle(self, job_path):
        nmap_output_file = os.path.join(job_path, OUTPUT_FILENAME)
        target_glob = os.path.join(job_path, TARGETS_GLOB)
        target_file = glob.glob(target_glob)[0]
        importer = NmapImporter(self.__db, self.__stage)
        importer.process(nmap_output_file, target_file)


class NessusSink(object):
    def __init__(self, db):
        self.__db = db

    def __str__(self):
        return "<NessusSink %s>" % (self.__db)

    def can_handle(self, job_path):
        job_name = os.path.basename(job_path)
        return job_name.startswith(STAGE.VULNSCAN)

    def handle(self, job_path):
        nessus_output_file = os.path.join(job_path, OUTPUT_FILENAME)
        importer = NessusImporter(self.__db)
        importer.process(nessus_output_file)


class NoOpSink(object):
    def __init__(self, db):
        self.__db = db
        self.__ch_db = CHDatabase(db)

    def __str__(self):
        return "<NoOpSink %s>" % (self.__db)

    def __transition_ip_file(self, filename, random_up_downs=False):
        with open(filename) as f:
            for ip_line in f:
                ip = netaddr.IPAddress(ip_line)
                if random_up_downs:
                    self.__ch_db.transition_host(ip, up=random.choice([True, False]))
                else:
                    self.__ch_db.transition_host(ip)

    def can_handle(self, job_path):
        return True

    def handle(self, job_path):
        target_glob = os.path.join(job_path, TARGETS_GLOB)
        target_file = glob.glob(target_glob)[0]
        job_name = os.path.basename(job_path)
        if job_name.startswith(STAGE.NETSCAN1) or job_name.startswith(STAGE.NETSCAN2):
            self.__transition_ip_file(target_file, True)
        else:
            self.__transition_ip_file(target_file, False)


class TryAgainSink(object):
    def __init__(self, db):
        self.__db = db
        self.__ch_db = CHDatabase(db)

    def __str__(self):
        return "<TryAgainSink %s>" % (self.__ch_db)

    def can_handle(self, job_path):
        return True

    def handle(self, job_path):
        target_glob = os.path.join(job_path, TARGETS_GLOB)
        target_file = glob.glob(target_glob)[0]
        with open(target_file) as f:
            for ip_line in f:
                ip = netaddr.IPAddress(ip_line)
                self.__ch_db.transition_host(ip, was_failure=True)
