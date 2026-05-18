# Global build arguments (available to all stages)
ARG PYTHON_VERSION=3.14.3
ARG DEBIAN_CODENAME=trixie
ARG UV_VERSION=0.7.12
ARG SOURCE_DATE_EPOCH

# Define uv image as a named stage so we can use the ARG in COPY --from
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

###############################################################################
# Compile stage - install production dependencies into a virtual environment
###############################################################################
FROM docker.io/library/python:${PYTHON_VERSION}-slim-${DEBIAN_CODENAME} AS compile

ARG SOURCE_DATE_EPOCH

# Copy uv from the named stage
COPY --from=uv /uv /usr/local/bin/uv

# Install git (required for fetching git-based dependencies)
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y git \
    && rm -rf /var/lib/apt/lists/*

# Set up the application home and create a virtual environment
ENV CISA_HOME=/home/cisa
RUN python3 -m venv ${CISA_HOME}/.venv

# Copy dependency files
COPY pyproject.toml uv.lock ${CISA_HOME}/

# Set a fallback version for setuptools-scm since .git is excluded from build context
ENV SETUPTOOLS_SCM_PRETEND_VERSION=0.0.1

# Install production dependencies into the virtual environment
RUN VIRTUAL_ENV="${CISA_HOME}/.venv" \
    uv sync --frozen --no-cache --no-dev --project "${CISA_HOME}"

# Set SOURCE_DATE_EPOCH for reproducible builds
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

###############################################################################
# Build stage - create the runtime image
###############################################################################
FROM docker.io/library/python:${PYTHON_VERSION}-slim-${DEBIAN_CODENAME} AS build

# Stage-scoped build arguments for user/group configuration
ARG CISA_UID=1000
ARG CISA_GID=${CISA_UID}
ARG CISA_USER=cisa
ARG SOURCE_DATE_EPOCH

# Create system group and user with configured UID/GID, no login shell, no password
RUN groupadd --gid ${CISA_GID} --system ${CISA_USER} \
    && useradd --uid ${CISA_UID} --gid ${CISA_GID} --system \
       --shell /usr/sbin/nologin --no-create-home ${CISA_USER} \
    && mkdir -p /home/${CISA_USER} \
    && chown ${CISA_UID}:${CISA_GID} /home/${CISA_USER}

# Install pinned system packages and clean apt lists in a single RUN
RUN apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
       openssh-client=1:10.0p1-7+deb13u4 \
       rsync=3.4.1+ds1-5+deb13u2 \
    && rm -rf /var/lib/apt/lists/*

# Python environment settings for container runtime
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set CISA_HOME for use in subsequent instructions
ENV CISA_HOME=/home/${CISA_USER}

# Copy virtual environment from compile stage with correct ownership
COPY --from=compile --chown=${CISA_UID}:${CISA_GID} ${CISA_HOME}/.venv ${CISA_HOME}/.venv

# Create symlink so the venv uses the system Python interpreter
RUN ln -sf /usr/local/bin/python3 ${CISA_HOME}/.venv/bin/python3

# Set PATH to include venv bin directory and define VIRTUAL_ENV
ENV PATH="${CISA_HOME}/.venv/bin:$PATH"
ENV VIRTUAL_ENV="${CISA_HOME}/.venv"

# Set SOURCE_DATE_EPOCH from build ARG for reproducible timestamps at runtime
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Copy application source with correct ownership
COPY --chown=${CISA_UID}:${CISA_GID} cyhy_commander/ ${CISA_HOME}/cyhy_commander/
COPY --chown=${CISA_UID}:${CISA_GID} scripts/ ${CISA_HOME}/scripts/

# Set group-read and group-execute permissions for OpenShift arbitrary UID support
RUN chmod -R g+rX ${CISA_HOME}/.venv ${CISA_HOME}/cyhy_commander ${CISA_HOME}/scripts

# OCI standard annotations
LABEL org.opencontainers.image.authors="github@cisa.dhs.gov" \
      org.opencontainers.image.vendor="Cybersecurity and Infrastructure Security Agency" \
      org.opencontainers.image.title="cyhy-commander" \
      org.opencontainers.image.source="https://github.com/cisagov/cyhy-commander"

# Set working directory
WORKDIR ${CISA_HOME}

# Health check for Docker and Docker Compose environments
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
    CMD ["python3", "-c", "import cyhy_commander"]

# Run as unprivileged user
USER ${CISA_USER}:${CISA_USER}

# Application entrypoint in exec form
ENTRYPOINT ["cyhy-commander"]
