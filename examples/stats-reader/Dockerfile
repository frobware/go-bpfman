# Build stage
FROM registry.access.redhat.com/ubi9/go-toolset:1.25 AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY examples/stats-reader/main.go ./

RUN CGO_ENABLED=0 go build -mod=vendor -o stats-reader .

# Runtime image
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY --from=builder /build/stats-reader /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/stats-reader"]
