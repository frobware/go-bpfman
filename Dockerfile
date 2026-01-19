# syntax=docker/dockerfile:1.4
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o bpffs-csi-driver .

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/bpffs-csi-driver /bpffs-csi-driver

ENTRYPOINT ["/bpffs-csi-driver"]
