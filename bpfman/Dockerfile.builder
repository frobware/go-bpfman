# Base builder image with BPF development tools
FROM fedora:latest

RUN dnf install -y \
    gcc \
    libbpf-devel \
    elfutils-libelf-devel \
    zlib-devel \
    pkgconf-pkg-config \
    && dnf clean all
