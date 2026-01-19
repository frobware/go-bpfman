.PHONY: all build clean proto generate

# Proto generation
PROTO_DIR := proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)
GOBPFMAN_DIR := internal/gobpfman
GENERATED_FILES := $(GOBPFMAN_DIR)/bpfman.pb.go $(GOBPFMAN_DIR)/bpfman_grpc.pb.go

# Build
BINARY := bpfman

all: generate build

build: $(BINARY)

$(BINARY): generate
	CGO_ENABLED=0 go build -o $@ ./cmd/bpfman

# Proto generation - generates Go code from .proto files
proto: $(GENERATED_FILES)

generate: proto

$(GOBPFMAN_DIR)/bpfman.pb.go $(GOBPFMAN_DIR)/bpfman_grpc.pb.go: $(PROTO_DIR)/bpfman.proto
	@mkdir -p $(GOBPFMAN_DIR)
	protoc \
		--go_out=$(GOBPFMAN_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(GOBPFMAN_DIR) \
		--go-grpc_opt=paths=source_relative \
		--proto_path=$(PROTO_DIR) \
		bpfman.proto

clean:
	rm -f $(BINARY)
	rm -f $(GOBPFMAN_DIR)/*.pb.go

# Install protoc plugins if needed
.PHONY: install-proto-tools
install-proto-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
