# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY examples/stats-reader/main.go ./

RUN CGO_ENABLED=0 go build -mod=vendor -o stats-reader .

# Runtime image
FROM alpine:latest

COPY --from=builder /build/stats-reader /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/stats-reader"]
