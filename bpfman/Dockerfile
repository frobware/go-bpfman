# Build stage for Go binary (uses cilium/ebpf and SQLite with CGO)
FROM golang:1.24 AS builder

RUN apt-get update && apt-get install -y gcc libc6-dev libsqlite3-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=1 go build -o bpfman ./cmd/bpfman

# Runtime image
FROM fedora:latest

RUN dnf install -y sqlite-libs && dnf clean all

COPY --from=builder /build/bpfman /usr/local/bin/
COPY testdata/stats.o /opt/bpf/stats.o

ENTRYPOINT ["/usr/local/bin/bpfman"]
CMD ["serve"]
