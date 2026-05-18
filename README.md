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
docker run --rm -v ./work:/home/cisa/work cyhy-commander work
```

The image runs as an unprivileged user (`cisa`, UID 1000) and supports
read-only root filesystems.  Mount writable paths as volumes for job working
directories.

For Kubernetes deployments, the image includes a probe script at
`/home/cisa/scripts/healthcheck.sh` supporting liveness and readiness checks:

```yaml
livenessProbe:
  exec:
    command: ["/home/cisa/scripts/healthcheck.sh", "liveness"]
readinessProbe:
  exec:
    command: ["/home/cisa/scripts/healthcheck.sh", "readiness"]
```

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
