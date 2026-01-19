# Base builder image with Go and SQLite development tools
FROM golang:1.24

RUN apt-get update && \
    apt-get install -y \
        gcc \
        libc6-dev \
        libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
