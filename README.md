# cyhy-commander #

Job orchestrator for the Cyber Hygiene (CyHy) scanning system.  Dispatches
scan jobs to nmap and Nessus scanner hosts via SSH/rsync, processes results,
and updates the database.

## Requirements ##

- Python 3.14+
- MongoDB 8.0+ or AWS DocumentDB (MongoDB 8.0 compatible)
- Scanner hosts running [cyhy-runner](https://github.com/cisagov/cyhy-runner)

## Installation ##

```bash
# Clone and install with uv
git clone https://github.com/cisagov/cyhy-commander.git
cd cyhy-commander
uv sync
```

## Configuration ##

Configuration is loaded from a TOML file via
[cyhy-config](https://github.com/cisagov/cyhy-config).  The following
locations are searched in order:

1. Path in the `CYHY_CONFIG_PATH` environment variable
1. AWS SSM Parameter Store path in `CYHY_CONFIG_SSM_PATH`
1. `./cyhy.toml` (current working directory)
1. `~/.cyhy/cyhy.toml` (user home)
1. `/etc/cyhy.toml` (system-wide)

See [`extras/cyhy-example.toml`](extras/cyhy-example.toml) for a fully
commented example.

## Usage ##

```bash
uv run cyhy-commander <working_dir>
```

## Docker ##

```bash
# Build the container image
docker build -t cyhy-commander .

# Build with custom UID/GID
docker build --build-arg CISA_UID=1001 --build-arg CISA_GID=1001 -t cyhy-commander .

# Verify the image works
docker run --rm cyhy-commander --help

# Run with a working directory (mount as volume)
docker run --rm -v ./work:/work cyhy-commander /work
```

The image runs as an unprivileged user (`cisa`, UID 1000) and supports
read-only root filesystems.  Mount writable paths as volumes for job working
directories.

### Working Directory ###

The default working directory is `/work`. The container's `ENTRYPOINT` invokes
`cyhy-commander /work` by default.

The Commander creates the subdirectories `done/`, `pushed/`, `failed/`, and
`drop/` within the working directory on startup if they do not already exist.

## Observability ##

cyhy-commander exposes Prometheus metrics and HTTP health check endpoints on a
dedicated metrics port (default 9090). The metrics server runs as a daemon
thread using a `ThreadingWSGIServer`, separate from the asyncio event loop.

### Prometheus Metrics ###

The following metrics are exposed at `GET /metrics` in Prometheus exposition
format:

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `cyhy_commander_work_cycle_duration_seconds` | Histogram | — | Wall-clock duration of each work cycle iteration |
| `cyhy_commander_jobs_pushed_total` | Counter | `stage` | Jobs successfully pushed to scanner hosts |
| `cyhy_commander_jobs_pulled_total` | Counter | `stage` | Completed jobs pulled from scanner hosts |
| `cyhy_commander_jobs_failed_total` | Counter | `stage` | Jobs that completed with non-zero exit code |
| `cyhy_commander_host_errors_total` | Counter | `host` | SSH/rsync exceptions per scanner host |
| `cyhy_commander_ips_pushed_total` | Counter | `stage` | IP addresses pushed in job bundles |
| `cyhy_commander_ips_pulled_total` | Counter | `stage`, `status` | IP addresses in pulled jobs (success/failure) |
| `cyhy_commander_last_cycle_completed_timestamp_seconds` | Gauge | — | Unix timestamp of last successful cycle completion |
| `cyhy_commander_last_db_success_timestamp_seconds` | Gauge | — | Unix timestamp of last successful DB operation |
| `cyhy_commander_scanner_connection_status` | Gauge | `host`, `workgroup` | 1 if last SSH/rsync to host succeeded, 0 if failed |

The `stage` label takes values: `NETSCAN1`, `NETSCAN2`, `PORTSCAN`, `VULNSCAN`.
The `status` label takes values: `success`, `failure`.

### Health Check Endpoints ###

All health endpoints are served on the metrics port alongside `/metrics`.

| Endpoint | Evaluates | Threshold | 200 Response | 503 Response |
|---|---|---|---|---|
| `GET /livez` | `last_cycle_completed_timestamp_seconds` | `CYHY_LIVENESS_THRESHOLD_SECONDS` (default 300s) | `ok` — last cycle within threshold, or first cycle not yet completed (startup grace) | `work cycle stale` — elapsed time since last cycle ≥ threshold |
| `GET /readyz` | `last_db_success_timestamp_seconds` | `CYHY_READINESS_THRESHOLD_SECONDS` (default 120s) | `ok` — last DB operation within threshold | `database connection stale` — elapsed time since last DB op ≥ threshold, or no DB op yet |
| `GET /startupz` | `_first_cycle_completed` flag | — | `ok` — first work cycle has completed | `first cycle not completed` — still initializing |

Requests to any other path on the metrics port return HTTP 404 with an empty
body.

### Environment Variables ###

| Variable | Purpose | Accepted Values | Default | Behavior When Unset |
|---|---|---|---|---|
| `CYHY_METRICS_PORT` | TCP port for the metrics/health server | Integer in range [1024, 65535] | `9090` | Uses default port 9090 |
| `CYHY_LIVENESS_THRESHOLD_SECONDS` | Maximum seconds since last completed work cycle before `/livez` returns 503 | Positive numeric value | `300` | Uses default of 300 seconds (5 minutes) |
| `CYHY_READINESS_THRESHOLD_SECONDS` | Maximum seconds since last successful DB operation before `/readyz` returns 503 | Integer in range [1, 3600] | `120` | Uses default of 120 seconds (2 minutes) |
| `CYHY_METRICS_BEARER_TOKEN` | Optional bearer token for authenticating requests to `/metrics` | String (minimum 8 characters recommended) | Unset (no auth) | Metrics served without authentication; security relies on NetworkPolicy |

If `CYHY_METRICS_PORT`, `CYHY_LIVENESS_THRESHOLD_SECONDS`, or
`CYHY_READINESS_THRESHOLD_SECONDS` is set to an invalid value, the server logs
a warning and falls back to the default.

If `CYHY_METRICS_BEARER_TOKEN` is set, all requests to `/metrics` must include
an `Authorization: Bearer <token>` header matching the configured value.
Requests with a missing, malformed, or incorrect token receive HTTP 401.
Health endpoints (`/livez`, `/readyz`, `/startupz`) are never authenticated.
If the token is shorter than 8 characters, a warning is logged but
authentication is still enforced.

### Kubernetes Deployment Example ###

The following manifest demonstrates `httpGet` probes, the `/work` volume mount,
the metrics container port, and a NetworkPolicy restricting access to the
metrics port:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cyhy-commander
  labels:
    app.kubernetes.io/name: cyhy-commander
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: cyhy-commander
  template:
    metadata:
      labels:
        app.kubernetes.io/name: cyhy-commander
    spec:
      containers:
        - name: cyhy-commander
          image: cyhy-commander:latest
          ports:
            - name: metrics
              containerPort: 9090
              protocol: TCP
          env:
            - name: CYHY_METRICS_PORT
              value: "9090"
            - name: CYHY_LIVENESS_THRESHOLD_SECONDS
              value: "300"
            - name: CYHY_READINESS_THRESHOLD_SECONDS
              value: "120"
          volumeMounts:
            - name: work
              mountPath: /work
          startupProbe:
            httpGet:
              path: /startupz
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 10
            failureThreshold: 30
          livenessProbe:
            httpGet:
              path: /livez
              port: 9090
            initialDelaySeconds: 0
            periodSeconds: 15
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: 9090
            initialDelaySeconds: 0
            periodSeconds: 10
            failureThreshold: 3
      volumes:
        - name: work
          emptyDir: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cyhy-commander-metrics
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: cyhy-commander
  policyTypes:
    - Ingress
  ingress:
    - from:
        # Allow Prometheus scraper pods
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: prometheus
        # Allow kubelet health probes (node-level traffic)
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 9090
```

The startup probe allows up to 5 minutes (30 failures × 10s period) for the
first work cycle to complete. While the startup probe has not yet succeeded,
Kubernetes does not execute the liveness or readiness probes.

### Docker HEALTHCHECK ###

For Docker Compose and non-Kubernetes environments, the image includes a
lightweight healthcheck script at `/home/cisa/scripts/healthcheck.py` that
queries the local metrics server using only the Python standard library:

```bash
# Liveness check (used by Docker HEALTHCHECK)
python3 /home/cisa/scripts/healthcheck.py liveness

# Readiness check
python3 /home/cisa/scripts/healthcheck.py readiness
```

Exit codes: 0 (healthy/ready), 1 (unhealthy/connection failure), 2 (invalid
subcommand).

## Development ##

```bash
# Install with test and dev extras
uv sync --extra test --extra dev

# Run tests
uv run pytest tests/unit tests/property

# Run pre-commit hooks
pre-commit run --all-files
```

## License ##

This project is in the worldwide public domain (CC0 1.0).
