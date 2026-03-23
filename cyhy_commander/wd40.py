"""Reset stuck scans back to the WAITING state.

Stuck scans are defined as scans that are in the RUNNING state but
have had no updates in a specified number of days. The number of days
can be specified and defaults to 1.

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

# Third-Party Libraries
from docopt import docopt
import pytz

# cisagov Libraries
from cyhy.db import database
from cyhy.core.common import STATUS


def setup_logging(debug):
    log_level = logging.INFO
    if debug:
        log_level = logging.DEBUG
    logging.basicConfig(
        format="%(asctime)-15s %(levelname)s %(message)s", level=log_level
    )


def compute_stuck_cutoff(days):
    # Current time in UTC
    now_utc = datetime.utcnow().replace(tzinfo=pytz.timezone("UTC"))
    return now_utc - timedelta(days=days)


def sync_tallies(db, owners):
    logging.info("Syncing tallies for all affected owners.")
    for owner in owners:
        logging.debug("Getting tally doc for %s.", owner)
        tally = db.TallyDoc.get_by_owner(owner)
        if tally is not None:
            logging.debug("Syncing tally for %s.", owner)
            tally.sync(db)
        else:
            logging.warning(
                "No existing tally doc found for %s.  You should verify that this is intentional, e.g., because the org has been retired.",
                owner,
            )
            continue


def main():
    args = docopt(__doc__, version="v1.0.0")

    # Set up logging
    setup_logging(args["--debug"])

    # Connect to database
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

    # Ensure that the --days argument is indeed a positive, nonzero
    # integer
    try:
        days = int(args["--days"])
    except (TypeError, ValueError):
        logging.critical(
            "Invalid value for --days (%r); it must be an integer.",
            args["--days"],
        )
        return 1
    else:
        if days < 0:
            logging.critical(
                "Invalid value for --days (%d); it must be a positive, nonzero integer.",
                days,
            )
            return 1

    # Compute the stuck cutoff
    stuck_cutoff = compute_stuck_cutoff(days)

    # Query for all hosts in the RUNNING state that have not been
    # updated since stuck_cutoff
    logging.info(
        "Querying for all host docs in the %s state that have not been updated since %s.",
        STATUS.RUNNING,
        stuck_cutoff,
    )
    query = {"status": STATUS.RUNNING, "last_change": {"$lt": stuck_cutoff}}
    hosts_cursor = db.HostDoc.collection.find(query, {"owner": True})

    # Gather a set of all owners associated with these host docs
    logging.info("Gathering all the owners associated with these host docs.")
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

    # Update host docs with stuck scans
    logging.info(
        "Updating the host docs with stuck scans by setting their status to %s.",
        STATUS.WAITING,
    )
    result = db.HostDoc.collection.update_many(
        query,
        {"$set": {"status": STATUS.WAITING}},
    )
    logging.info(
        "Updated %d host documents from %s to %s.",
        result.modified_count,
        STATUS.RUNNING,
        STATUS.WAITING,
    )

    # Sync tallies for affected owners
    sync_tallies(db, owners)
