# Build stage for Go binary
FROM golang:1.24 AS go-builder

WORKDIR /build
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/

RUN go build -o bpfman ./cmd/bpfman

# Build stage for C shim (uses pre-built base with dev packages)
FROM bpfman-builder:latest AS c-builder

WORKDIR /build
COPY bpfman-kernel/ ./

RUN make

# Runtime image
FROM fedora:latest

RUN dnf install -y \
    libbpf \
    elfutils-libelf \
    && dnf clean all

COPY --from=go-builder /build/bpfman /usr/local/bin/
COPY --from=c-builder /build/bpfman-kernel /usr/local/bin/
COPY testdata/stats.o /opt/bpf/stats.o

ENTRYPOINT ["/usr/local/bin/bpfman"]
