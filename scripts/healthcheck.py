#!/usr/bin/env python3
"""Docker HEALTHCHECK probe script for cyhy-commander.

Usage:
    healthcheck.py liveness   - Check /livez endpoint
    healthcheck.py readiness  - Check /readyz endpoint

Exit codes:
    0 - healthy/ready (HTTP 200)
    1 - unhealthy/not-ready (non-200 or connection failure)
    2 - usage error (invalid subcommand)
"""

import os
import sys
import urllib.error
import urllib.request

METRICS_PORT = int(os.environ.get("CYHY_METRICS_PORT", "9090"))
TIMEOUT = 2  # seconds

SUBCOMMANDS = {
    "liveness": "/livez",
    "readiness": "/readyz",
}


def check(endpoint: str) -> int:
    """GET http://localhost:{port}/{endpoint}, return 0 on 200, 1 otherwise."""
    url = f"http://localhost:{METRICS_PORT}{endpoint}"
    try:
        response = urllib.request.urlopen(url, timeout=TIMEOUT)
        if response.status == 200:
            return 0
        return 1
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return 1


def main() -> int:
    """Parse subcommand and dispatch to check()."""
    if len(sys.argv) != 2 or sys.argv[1] not in SUBCOMMANDS:
        print(
            "Usage: healthcheck.py liveness|readiness\n"
            "\n"
            "Subcommands:\n"
            "  liveness   - Check /livez endpoint\n"
            "  readiness  - Check /readyz endpoint\n"
            "\n"
            "Exit codes:\n"
            "  0 - healthy/ready (HTTP 200)\n"
            "  1 - unhealthy/not-ready (non-200 or connection failure)\n"
            "  2 - usage error (invalid subcommand)",
            file=sys.stderr,
        )
        return 2

    subcommand = sys.argv[1]
    endpoint = SUBCOMMANDS[subcommand]
    return check(endpoint)


if __name__ == "__main__":
    sys.exit(main())
