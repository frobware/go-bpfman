# syntax=docker/dockerfile:1.4
FROM fedora:41

RUN dnf install -y bpftool && dnf clean all

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
