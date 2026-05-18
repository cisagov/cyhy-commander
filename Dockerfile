# Global build arguments (available to all stages)
ARG PYTHON_VERSION=3.14.3
ARG DEBIAN_CODENAME=trixie
ARG UV_VERSION=0.7.12
ARG SOURCE_DATE_EPOCH

###############################################################################
# Compile stage - install production dependencies into a virtual environment
###############################################################################
FROM docker.io/library/python:${PYTHON_VERSION}-slim-${DEBIAN_CODENAME} AS compile

ARG UV_VERSION
ARG SOURCE_DATE_EPOCH

# Copy uv from the official image
COPY --from=ghcr.io/astral-sh/uv:${UV_VERSION} /uv /usr/local/bin/uv

# Set up the application home and create a virtual environment
ENV CISA_HOME=/home/cisa
RUN python3 -m venv ${CISA_HOME}/.venv

# Copy dependency files
COPY pyproject.toml uv.lock ${CISA_HOME}/

# Install production dependencies into the virtual environment
RUN VIRTUAL_ENV="${CISA_HOME}/.venv" \
    uv sync --frozen --no-cache --no-dev --project "${CISA_HOME}"

# Set SOURCE_DATE_EPOCH for reproducible builds
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
