# syntax=docker/dockerfile:1.4
# Build stage for Go binary (uses cilium/ebpf and SQLite with CGO)
ARG BUILDER_IMAGE=bpfman-builder:dev
FROM ${BUILDER_IMAGE} AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -o bpfman ./cmd/bpfman

# Runtime image
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

RUN microdnf install -y sqlite-libs && microdnf clean all

COPY --from=builder /build/bpfman /usr/local/bin/
COPY testdata/stats.o /opt/bpf/stats.o

ENTRYPOINT ["/usr/local/bin/bpfman"]
CMD ["serve"]
