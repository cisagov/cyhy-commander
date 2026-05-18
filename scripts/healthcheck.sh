#!/bin/sh
# Health check probe script for cyhy-commander container.
# Supports Docker HEALTHCHECK and Kubernetes liveness/readiness probes.
#
# Usage: healthcheck.sh [liveness|readiness]
#   liveness  - Verify cyhy-commander process is running (not zombie)
#   readiness - Verify database connectivity within 2 seconds
#   (no args) - Default: verify Python can import cyhy_commander package
#
# Exit codes:
#   0 - healthy
#   1 - unhealthy

set -e

# --- Liveness check ---
# Verifies the cyhy-commander process exists and is not in a zombie state.
check_liveness() {
    # Find the PID of the cyhy-commander process
    pid=$(pgrep -f "cyhy-commander" 2>/dev/null | head -n 1)

    if [ -z "$pid" ]; then
        echo "UNHEALTHY: cyhy-commander process not found"
        return 1
    fi

    # Check if the process is a zombie via /proc
    if [ -f "/proc/${pid}/status" ]; then
        state=$(grep -i "^State:" "/proc/${pid}/status" 2>/dev/null | awk '{print $2}')
        if [ "$state" = "Z" ]; then
            echo "UNHEALTHY: cyhy-commander process is zombie (pid=$pid)"
            return 1
        fi
    else
        # Fallback: verify process is alive with kill -0
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "UNHEALTHY: cyhy-commander process not responding (pid=$pid)"
            return 1
        fi
    fi

    return 0
}

# --- Readiness check ---
# Verifies database connectivity within 2 seconds using the application config.
check_readiness() {
    python3 -c "
import sys
import signal

# Enforce 2-second timeout
def timeout_handler(signum, frame):
    print('UNHEALTHY: database connection timed out (2s)')
    sys.exit(1)

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(2)

try:
    from cyhy_commander.config_model import load_config
    from pymongo import MongoClient

    config = load_config()
    client = MongoClient(config.database.uri, serverSelectionTimeoutMS=2000)
    # Lightweight ping to verify connectivity
    client.admin.command('ping')
    client.close()
except SystemExit:
    raise
except Exception as e:
    print(f'UNHEALTHY: database connection failed: {e}')
    sys.exit(1)
" 2>/dev/null

    return $?
}

# --- Default check (Docker HEALTHCHECK) ---
# Verifies the Python runtime can import the cyhy_commander package.
check_import() {
    if python3 -c "import cyhy_commander" 2>/dev/null; then
        return 0
    else
        echo "UNHEALTHY: cannot import cyhy_commander package"
        return 1
    fi
}

# --- Main ---
case "${1:-}" in
    liveness)
        check_liveness
        ;;
    readiness)
        check_readiness
        ;;
    *)
        check_import
        ;;
esac
