# syntax=docker/dockerfile:1.4
FROM registry.access.redhat.com/ubi9/go-toolset:1.24 AS builder

USER root
WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o bpffs-csi-driver .

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

RUN microdnf install -y ca-certificates && microdnf clean all

COPY --from=builder /app/bpffs-csi-driver /bpffs-csi-driver

ENTRYPOINT ["/bpffs-csi-driver"]
