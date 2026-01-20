.PHONY: help build test clean docker-build-csi kind-load deploy-driver delete-driver redeploy logs logs-registrar status deploy-app-pod delete-app-pod delete-all docker-build-bpfman docker-build-bpfman-builder docker-clean-bpfman-builder kind-load-bpfman deploy-bpfman delete-bpfman logs-bpfman deploy-bpfman-test delete-bpfman-test bpfman-proto bpfman-clean bpfman-build bpfman-test-grpc

help:
	@echo "CSI Driver:"
	@echo "  build              Build csi-driver binary"
	@echo "  test               Run csi-driver tests"
	@echo "  docker-build-csi   Build csi-driver container image"
	@echo "  deploy-driver      Deploy csi-driver to kind cluster"
	@echo "  delete-driver      Remove csi-driver from cluster"
	@echo ""
	@echo "bpfman:"
	@echo "  bpfman-build       Build bpfman binary"
	@echo "  bpfman-proto       Generate protobuf/gRPC stubs"
	@echo "  bpfman-clean       Remove generated files and binary"
	@echo "  docker-build-bpfman Build bpfman container image"
	@echo "  deploy-bpfman      Deploy bpfman to kind cluster"
	@echo "  delete-bpfman      Remove bpfman from cluster"
	@echo "  bpfman-test-grpc   Run gRPC integration tests"
	@echo ""
	@echo "Combined:"
	@echo "  deploy-app-pod     Deploy test pod with CSI volume"
	@echo "  delete-all         Remove all components"
	@echo "  clean              Remove all build artifacts"

IMAGE_NAME ?= bpffs-csi-driver
IMAGE_TAG ?= dev
BPFMAN_IMAGE ?= bpfman
BPFMAN_BUILDER_IMAGE ?= bpfman-builder
KIND_CLUSTER ?= bpfman-deployment
NAMESPACE ?= kube-system
BIN_DIR ?= bin

build:
	cd csi-driver && go build -o ../$(BIN_DIR)/bpffs-csi-driver .

test:
	cd csi-driver && go test -v ./...

clean: bpfman-clean
	$(RM) -r $(BIN_DIR)

bpfman-clean:
	$(RM) -r bpfman/internal/server/pb/
	$(RM) $(BIN_DIR)/bpfman

bpfman-build: bpfman-proto
	cd bpfman && go build -o ../$(BIN_DIR)/bpfman ./cmd/bpfman

docker-build-csi:
	docker buildx build --builder=default --load -t $(IMAGE_NAME):$(IMAGE_TAG) csi-driver/

kind-load: docker-build-csi
	kind load docker-image $(IMAGE_NAME):$(IMAGE_TAG) --name $(KIND_CLUSTER)

deploy-driver: kind-load
	kubectl apply -f deploy/csidriver.yaml -f deploy/daemonset.yaml

delete-driver:
	kubectl delete -f deploy/csidriver.yaml -f deploy/daemonset.yaml --ignore-not-found

redeploy: delete-driver deploy-driver

logs:
	kubectl -n $(NAMESPACE) logs -l app=bpffs-csi-node -c csi-driver -f

logs-registrar:
	kubectl -n $(NAMESPACE) logs -l app=bpffs-csi-node -c node-driver-registrar -f

status:
	@echo "=== CSI Driver Pod ==="
	@kubectl -n $(NAMESPACE) get pods -l app=bpffs-csi-node -o wide
	@echo ""
	@echo "=== CSI Drivers ==="
	@kubectl get csidrivers

docker-build-bpfman-builder:
	@docker image inspect $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) >/dev/null 2>&1 || \
		docker buildx build --builder=default --load -t $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) -f bpfman/Dockerfile.builder bpfman/

docker-clean-bpfman-builder:
	-docker rmi $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG)

# Proto generation for bpfman gRPC API
BPFMAN_PROTO_DIR := bpfman/proto
BPFMAN_PB_DIR := bpfman/internal/server/pb

bpfman-proto: $(BPFMAN_PB_DIR)/bpfman.pb.go $(BPFMAN_PB_DIR)/bpfman_grpc.pb.go

$(BPFMAN_PB_DIR)/bpfman.pb.go $(BPFMAN_PB_DIR)/bpfman_grpc.pb.go: $(BPFMAN_PROTO_DIR)/bpfman.proto
	mkdir -p $(BPFMAN_PB_DIR)
	protoc --go_out=$(BPFMAN_PB_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(BPFMAN_PB_DIR) --go-grpc_opt=paths=source_relative \
		--proto_path=$(BPFMAN_PROTO_DIR) \
		$<

docker-build-bpfman: docker-build-bpfman-builder bpfman/testdata/stats.o bpfman-proto
	docker buildx build --builder=default --load --build-arg BUILDER_IMAGE=$(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) -t $(BPFMAN_IMAGE):$(IMAGE_TAG) bpfman/

kind-load-bpfman: docker-build-bpfman
	kind load docker-image $(BPFMAN_IMAGE):$(IMAGE_TAG) --name $(KIND_CLUSTER)

deploy-bpfman: kind-load-bpfman
	kubectl apply -f deploy/bpfman.yaml
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpfman --timeout=60s

delete-bpfman:
	kubectl delete -f deploy/bpfman.yaml --ignore-not-found

logs-bpfman:
	kubectl -n $(NAMESPACE) logs -l app=bpfman -f

deploy-app-pod: deploy-driver deploy-bpfman
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpffs-csi-node --timeout=60s
	kubectl apply -f deploy/app-pod.yaml
	kubectl wait --for=condition=Ready pod/bpffs-app-pod --timeout=30s
	@echo ""
	@echo "=== Volume mount ==="
	@kubectl exec bpffs-app-pod -- mount | grep /bpf

delete-app-pod:
	kubectl delete -f deploy/app-pod.yaml --ignore-not-found

delete-all: delete-app-pod delete-driver delete-bpfman

# bpfman testdata
BPFMAN_HACKS_DIR ?= $(HOME)/src/github.com/frobware/bpfman-hacks

bpfman/testdata/stats.o: $(BPFMAN_HACKS_DIR)/stats/bpf/stats.o
	mkdir -p bpfman/testdata
	cp $< $@

deploy-bpfman-test: kind-load-bpfman
	kubectl apply -f bpfman/deploy/test-pod.yaml
	kubectl wait --for=condition=Ready pod/bpfman-test --timeout=30s

delete-bpfman-test:
	kubectl delete -f bpfman/deploy/test-pod.yaml --ignore-not-found

bpfman-test-grpc: docker-build-bpfman
	BPFMAN_IMAGE=$(BPFMAN_IMAGE):$(IMAGE_TAG) bpfman/scripts/test-grpc.sh
