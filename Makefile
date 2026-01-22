all: bpfman-build

help:
	@echo "Build:"
	@echo "  build-all                   Build all binaries"
	@echo "  clean                       Remove all build artifacts"
	@echo "  docker-build-all            Build all container images"
	@echo "  test                        Run all tests"
	@echo ""
	@echo "bpfman (with integrated CSI):"
	@echo "  bpfman-build                Build bpfman binary"
	@echo "  bpfman-clean                Remove generated files and binary"
	@echo "  bpfman-delete               Remove bpfman from cluster"
	@echo "  bpfman-deploy               Deploy bpfman to KIND cluster"
	@echo "  bpfman-logs                 Follow bpfman logs"
	@echo "  bpfman-proto                Generate protobuf/gRPC stubs"
	@echo "  bpfman-test-grpc            Run gRPC integration tests"
	@echo "  docker-build-bpfman         Build bpfman container image"
	@echo "  docker-build-bpfman-cgo     Build bpfman with CGO (if needed)"
	@echo ""
	@echo "Example stats-reader app:"
	@echo "  docker-build-stats-reader   Build stats-reader container image"
	@echo "  stats-reader-delete         Remove stats-reader pod"
	@echo "  stats-reader-deploy         Deploy stats-reader pod"
	@echo "  stats-reader-logs           Follow stats-reader logs"
	@echo ""
	@echo "CSI conformance testing:"
	@echo "  docker-build-csi-sanity     Build csi-sanity container image"
	@echo ""
	@echo "KIND cluster:"
	@echo "  kind-create                 Create KIND cluster with bpffs mounted"
	@echo "  kind-delete                 Delete KIND cluster"
	@echo ""
	@echo "Dispatchers:"
	@echo "  dispatchers-build           Build XDP/TC dispatcher BPF programs"
	@echo "  dispatchers-clean           Remove dispatcher build artifacts"
	@echo ""
	@echo "Combined:"
	@echo "  kind-undeploy-all           Remove all components from KIND cluster"

IMAGE_TAG ?= dev
BPFMAN_IMAGE ?= bpfman
BPFMAN_BUILDER_IMAGE ?= bpfman-builder
KIND_CLUSTER ?= bpfman-go
NAMESPACE ?= bpfman
STATS_READER_IMAGE ?= stats-reader
BIN_DIR ?= bin

# Aggregate targets
build-all: bpfman-build

docker-build-all: docker-build-bpfman docker-build-stats-reader docker-build-csi-sanity

clean: bpfman-clean dispatchers-clean
	$(RM) -r $(BIN_DIR)

test:
	go test -v ./...

# bpfman targets
# Note: bpfman-proto is not a dependency here since pb files are committed.
# Run 'make bpfman-proto' explicitly after modifying proto/bpfman.proto.
bpfman-build:
	go fmt ./...
	go vet ./...
	CGO_ENABLED=0 go build -mod=vendor -o $(BIN_DIR)/bpfman ./cmd/bpfman

bpfman-clean:
	$(RM) $(BIN_DIR)/bpfman

# Proto generation for bpfman gRPC API
BPFMAN_PROTO_DIR := proto
BPFMAN_PB_DIR := pkg/bpfman/server/pb

bpfman-proto: $(BPFMAN_PB_DIR)/bpfman.pb.go $(BPFMAN_PB_DIR)/bpfman_grpc.pb.go

$(BPFMAN_PB_DIR)/bpfman.pb.go $(BPFMAN_PB_DIR)/bpfman_grpc.pb.go: $(BPFMAN_PROTO_DIR)/bpfman.proto
	mkdir -p $(BPFMAN_PB_DIR)
	protoc --go_out=$(BPFMAN_PB_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(BPFMAN_PB_DIR) --go-grpc_opt=paths=source_relative \
		--proto_path=$(BPFMAN_PROTO_DIR) \
		$<

docker-build-bpfman: testdata/stats.o
	docker buildx build --builder=default --load -t $(BPFMAN_IMAGE):$(IMAGE_TAG) -f Dockerfile.bpfman .

# CGO builder image (for future use if CGO is needed again)
# Usage: make docker-build-bpfman-builder && make docker-build-bpfman-cgo
docker-build-bpfman-builder:
	docker buildx build --builder=default --load -t $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) -f Dockerfile.bpfman-builder .

docker-build-bpfman-cgo: docker-build-bpfman-builder testdata/stats.o
	docker buildx build --builder=default --load --build-arg BUILDER_IMAGE=$(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) -t $(BPFMAN_IMAGE):$(IMAGE_TAG) -f Dockerfile.bpfman .

docker-clean-bpfman-builder:
	-docker rmi $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG)

bpfman-kind-load: docker-build-bpfman
	kind load docker-image $(BPFMAN_IMAGE):$(IMAGE_TAG) --name $(KIND_CLUSTER)

bpfman-deploy: bpfman-kind-load
	kubectl apply -f manifests/csidriver.yaml -f manifests/bpfman.yaml
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpfman-daemon-go --timeout=60s

bpfman-delete:
	kubectl delete -f manifests/bpfman.yaml -f manifests/csidriver.yaml --ignore-not-found

bpfman-logs:
	kubectl -n $(NAMESPACE) logs -l app=bpfman-daemon-go -c bpfman -f

bpfman-deploy-test: bpfman-kind-load
	kubectl apply -f manifests/bpfman-test-pod.yaml
	kubectl wait --for=condition=Ready pod/bpfman-test --timeout=30s

bpfman-delete-test:
	kubectl delete -f manifests/bpfman-test-pod.yaml --ignore-not-found

bpfman-test-grpc: docker-build-bpfman
	BPFMAN_IMAGE=$(BPFMAN_IMAGE):$(IMAGE_TAG) scripts/test-grpc.sh

# bpfman testdata
BPFMAN_HACKS_DIR ?= $(HOME)/src/github.com/frobware/bpfman-hacks

testdata/stats.o: $(BPFMAN_HACKS_DIR)/stats/bpf/stats.o
	mkdir -p testdata
	cp $< $@

# stats-reader example app
docker-build-stats-reader:
	docker buildx build --builder=default --load -t $(STATS_READER_IMAGE):$(IMAGE_TAG) -f examples/stats-reader/Dockerfile .

stats-reader-kind-load: docker-build-stats-reader
	kind load docker-image $(STATS_READER_IMAGE):$(IMAGE_TAG) --name $(KIND_CLUSTER)

stats-reader-deploy: stats-reader-kind-load
	kubectl apply -f manifests/stats-reader.yaml
	kubectl wait --for=condition=Ready pod/stats-reader --timeout=30s

stats-reader-delete:
	kubectl delete -f manifests/stats-reader.yaml --ignore-not-found

stats-reader-logs:
	kubectl logs -f stats-reader

# CSI conformance testing
CSI_SANITY_IMAGE ?= csi-sanity

docker-build-csi-sanity:
	docker buildx build --builder=default --load -t $(CSI_SANITY_IMAGE):$(IMAGE_TAG) -f Dockerfile.csi-sanity .

# KIND cluster management
kind-create:
	kind create cluster --name $(KIND_CLUSTER) --config kind-config.yaml
	@echo "Mounting bpffs on KIND nodes..."
	@for node in $$(kind get nodes --name $(KIND_CLUSTER)); do \
		docker exec $$node mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true; \
	done
	@echo "KIND cluster $(KIND_CLUSTER) created with bpffs mounted"

kind-delete:
	kind delete cluster --name $(KIND_CLUSTER)

# Dispatcher targets
dispatchers-build:
	$(MAKE) -C dispatchers

dispatchers-clean:
	$(MAKE) -C dispatchers clean

# Combined targets
kind-undeploy-all: stats-reader-delete bpfman-delete

.PHONY: \
	bpfman-build \
	bpfman-clean \
	bpfman-delete \
	bpfman-delete-test \
	bpfman-deploy \
	bpfman-deploy-test \
	bpfman-kind-load \
	bpfman-logs \
	bpfman-proto \
	bpfman-test-grpc \
	build-all \
	clean \
	dispatchers-build \
	dispatchers-clean \
	docker-build-all \
	docker-build-bpfman \
	docker-build-bpfman-builder \
	docker-build-bpfman-cgo \
	docker-build-csi-sanity \
	docker-build-stats-reader \
	docker-clean-bpfman-builder \
	help \
	kind-create \
	kind-delete \
	kind-undeploy-all \
	stats-reader-delete \
	stats-reader-deploy \
	stats-reader-logs \
	test
