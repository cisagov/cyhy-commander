#!/usr/bin/env python

"""Nessus file import tool.

Usage:
  cyhy-nessus-import [options] FILE
  cyhy-nessus-import (-h | --help)

Options:
  -g --gzipped           Process a gzipped file.
  -h --help              Show this message.
  --log-level=LEVEL      If specified, then the log level will be set to
                         the specified value.  Valid values are "debug", "info",
                         "warning", "error", and "critical". [default: warning]
  -s SECTION --section=SECTION   Configuration section to use.

"""

import logging
import sys

import docopt

from cyhy.db import database
from cyhy_commander.nessus import NessusImporter

# from ._version import __version__
__version__ = "0.0.2"


def import_nessus(db, filename, gzipped=True):
    """Import a nessus file."""
    logging.info("Starting import of Nessus file: " + filename)
    # prevent hosts from changing stage/status during manual import
    importer = NessusImporter(db, manual_scan=True)
    importer.process(filename, gzipped=gzipped)
    logging.info("Import completed.")


def main():
    """Set up logging and call the import function."""
    args = docopt.docopt(__doc__, version=__version__)

    # Set up logging
    log_level = args["--log-level"]
    try:
        logging.basicConfig(
            format="%(asctime)-15s %(levelname)s %(message)s", level=log_level.upper()
        )
    except ValueError:
        logging.critical(
            log_level + " is not a valid logging level.  Possible values "
            "are debug, info, warning, and error."
        )
        return 1

    db = database.db_from_config(args["--section"])

    import_nessus(db, args["FILE"], gzipped=args["--gzipped"])

    # Stop logging and clean up
    logging.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
