# Build stage for Go binary (uses cilium/ebpf, no CGO)
FROM golang:1.24 AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 go build -o bpfman ./cmd/bpfman

# Runtime image - minimal, no libbpf needed
FROM fedora:latest

COPY --from=builder /build/bpfman /usr/local/bin/
COPY testdata/stats.o /opt/bpf/stats.o

ENTRYPOINT ["/usr/local/bin/bpfman"]
