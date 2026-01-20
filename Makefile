.PHONY: help build-all docker-build-all clean test csi-build csi-test docker-build-csi csi-kind-load csi-deploy csi-delete csi-redeploy csi-logs csi-logs-registrar csi-status bpfman-build bpfman-proto bpfman-clean docker-build-bpfman docker-build-bpfman-builder docker-build-bpfman-cgo docker-clean-bpfman-builder bpfman-kind-load bpfman-deploy bpfman-delete bpfman-logs bpfman-deploy-test bpfman-delete-test bpfman-test-grpc docker-build-stats-reader stats-reader-deploy stats-reader-delete stats-reader-logs docker-build-csi-sanity delete-all

help:
	@echo "Build:"
	@echo "  build-all          Build all binaries"
	@echo "  docker-build-all   Build all container images"
	@echo "  clean              Remove all build artifacts"
	@echo "  test               Run all tests"
	@echo ""
	@echo "bpfman (unified with CSI):"
	@echo "  bpfman-build       Build bpfman binary (includes CSI support)"
	@echo "  bpfman-proto       Generate protobuf/gRPC stubs"
	@echo "  bpfman-clean       Remove generated files and binary"
	@echo "  docker-build-bpfman Build bpfman container image"
	@echo "  bpfman-deploy      Deploy bpfman with CSI to kind cluster"
	@echo "  bpfman-delete      Remove bpfman from cluster"
	@echo "  bpfman-logs        Follow bpfman logs"
	@echo "  bpfman-test-grpc   Run gRPC integration tests"
	@echo ""
	@echo "Standalone CSI Driver (legacy):"
	@echo "  csi-build          Build standalone csi-driver binary"
	@echo "  csi-test           Run csi-driver tests"
	@echo "  docker-build-csi   Build standalone csi-driver container image"
	@echo "  csi-deploy         Deploy standalone csi-driver to kind cluster"
	@echo "  csi-delete         Remove standalone csi-driver from cluster"
	@echo "  csi-logs           Follow csi-driver logs"
	@echo "  csi-status         Show csi-driver status"
	@echo ""
	@echo "Example stats-reader app:"
	@echo "  docker-build-stats-reader  Build stats-reader container image"
	@echo "  stats-reader-deploy        Deploy stats-reader pod"
	@echo "  stats-reader-delete        Remove stats-reader pod"
	@echo "  stats-reader-logs          Follow stats-reader logs"
	@echo ""
	@echo "Combined:"
	@echo "  delete-all         Remove all components"

IMAGE_NAME ?= bpffs-csi-driver
IMAGE_TAG ?= dev
BPFMAN_IMAGE ?= bpfman
BPFMAN_BUILDER_IMAGE ?= bpfman-builder
KIND_CLUSTER ?= bpfman-deployment
NAMESPACE ?= bpfman
STATS_READER_IMAGE ?= stats-reader
BIN_DIR ?= bin

# Aggregate targets
build-all: csi-build bpfman-build

docker-build-all: docker-build-csi docker-build-bpfman

clean: bpfman-clean
	$(RM) -r $(BIN_DIR)

test:
	go test -v ./...

# CSI Driver targets
csi-build:
	CGO_ENABLED=0 go build -mod=vendor -o $(BIN_DIR)/bpffs-csi-driver ./cmd/csi-driver

csi-test:
	go test -v ./pkg/csi/...

docker-build-csi:
	docker buildx build --builder=default --load -t $(IMAGE_NAME):$(IMAGE_TAG) -f Dockerfile.csi-driver .

csi-kind-load: docker-build-csi
	kind load docker-image $(IMAGE_NAME):$(IMAGE_TAG) --name $(KIND_CLUSTER)

csi-deploy: csi-kind-load
	kubectl apply -f deploy/csidriver.yaml -f deploy/daemonset.yaml

csi-delete:
	kubectl delete -f deploy/csidriver.yaml -f deploy/daemonset.yaml --ignore-not-found

csi-redeploy: csi-delete csi-deploy

csi-logs:
	kubectl -n $(NAMESPACE) logs -l app=bpffs-csi-node -c csi-driver -f

csi-logs-registrar:
	kubectl -n $(NAMESPACE) logs -l app=bpffs-csi-node -c node-driver-registrar -f

csi-status:
	@echo "=== CSI Driver Pod ==="
	kubectl -n $(NAMESPACE) get pods -l app=bpffs-csi-node -o wide
	@echo ""
	@echo "=== CSI Drivers ==="
	kubectl get csidrivers

# bpfman targets
# Note: bpfman-proto is not a dependency here since pb files are committed.
# Run 'make bpfman-proto' explicitly after modifying proto/bpfman.proto.
bpfman-build:
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
	kubectl apply -f deploy/csidriver.yaml -f deploy/bpfman.yaml
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpfman-daemon-go --timeout=60s

bpfman-delete:
	kubectl delete -f deploy/bpfman.yaml -f deploy/csidriver.yaml --ignore-not-found

bpfman-logs:
	kubectl -n $(NAMESPACE) logs -l app=bpfman-daemon-go -c bpfman -f

bpfman-deploy-test: bpfman-kind-load
	kubectl apply -f deploy/bpfman-test-pod.yaml
	kubectl wait --for=condition=Ready pod/bpfman-test --timeout=30s

bpfman-delete-test:
	kubectl delete -f deploy/bpfman-test-pod.yaml --ignore-not-found

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
	kubectl apply -f deploy/stats-reader.yaml
	kubectl wait --for=condition=Ready pod/stats-reader --timeout=30s

stats-reader-delete:
	kubectl delete -f deploy/stats-reader.yaml --ignore-not-found

stats-reader-logs:
	kubectl logs -f stats-reader

# CSI conformance testing
CSI_SANITY_IMAGE ?= csi-sanity

docker-build-csi-sanity:
	docker buildx build --builder=default --load -t $(CSI_SANITY_IMAGE):$(IMAGE_TAG) -f Dockerfile.csi-sanity .

# Combined targets
delete-all: stats-reader-delete bpfman-delete
