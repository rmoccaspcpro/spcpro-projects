FROM mcr.microsoft.com/devcontainers/python:3.11

# Install additional system dependencies if needed
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
    sqlite3 \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# Create data directory for SQLite database
RUN mkdir -p /workspace/data && chown -R vscode:vscode /workspace
