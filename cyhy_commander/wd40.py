"""Reset stuck scans back to the WAITING state.

Usage:
  cyhy-wd40 [options]
  cyhy-wd40 (-h | --help)
  cyhy-wd40 --version

Options:
  -d --debug                      Use verbose logging
  -f FILE --config-file=FILE      Configuration file to use
  -h --help                       Show this screen
  -s SECTION --section=SECTION    Configuration section to use
  -t DAYS --days=DAYS             Number of days a scan should go without an update before being considered stuck [default: 1]
  --version                       Show version
"""

# Standard Python Libraries
from datetime import datetime, timedelta
import logging
import pytz

# Third-Party Libraries
from docopt import docopt

# cisagov Libraries
from cyhy.db import database
from cyhy.core.common import STATUS


def main():
    args = docopt(__doc__, version="v1.0.0")

    # Set up logging
    log_level = logging.WARNING
    if args["--debug"]:
        log_level = logging.DEBUG
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level
    )

    config = args["--config-file"]
    section = args["--section"]
    try:
        db = database.db_from_config(section, config)
    except Exception:
        logging.critical(
            "Unable to connect to the database server in section %s of %s",
            section,
            config,
            exc_info=True,
        )
        return 1

    # Today's date at midnight UTC
    date_today = datetime.utcnow().replace(
        hour=0, minute=0, second=0, microsecond=0, tzinfo=pytz.timezone("UTC")
    )
    try:
        days = int(args["--days"])
    except (TypeError, ValueError):
        logging.critical(
            "Invalid value for --days (%r); it must be an integer.",
            args["--days"],
        )
        return 1
    stuck_cutoff = date_today - timedelta(days=days)

    logging.info(
        "Querying for all host docs in the %s state that have not been updated since %s.",
        STATUS.RUNNING,
        stuck_cutoff,
    )
    hosts_cursor = db.hosts.find(
        {"status": STATUS.RUNNING, "last_change": {"$lt": stuck_cutoff}}
    )

    logging.info("Gathering a list of all the owners associated with these host docs.")
    owners = set()
    host_count = 0
    for host in hosts_cursor:
        owners.add(host["owner"])
        host_count += 1
    logging.info(
        "%d unique owners found in %d host documents with stuck scans",
        len(owners),
        host_count,
    )

    logging.info(
        "Updating the host docs with stuck scans by setting their status to %s.", STATUS.WAITING
    )
    result = db.hosts.update_many(
        {"status": STATUS.RUNNING, "last_change": {"$lt": stuck_cutoff}},
        {"$set": {"status": STATUS.WAITING}},
    )
    logging.info(
        "Updated %d host documents from %s to %s.",
        result.modified_count,
        STATUS.RUNNING,
        STATUS.WAITING,
    )

    logging.info("Syncing tallies for all affected owners.")
    for owner in owners:
        logging.debug("Getting tally doc for %s.", owner)
        tally = db.TallyDoc.get_by_owner(owner)
        if tally is None:
            logging.warning(
                "No existing tally doc found for %s.  Creating a new one.", owner
            )
            tally = db.TallyDoc()
