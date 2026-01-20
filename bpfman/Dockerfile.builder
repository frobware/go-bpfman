# Base builder image with Go and SQLite development tools
FROM registry.access.redhat.com/ubi9/go-toolset:1.24

USER root
RUN dnf install -y sqlite-devel && dnf clean all
