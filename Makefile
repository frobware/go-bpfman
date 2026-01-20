.PHONY: help clean csi-build csi-test csi-docker-build csi-kind-load csi-deploy csi-delete csi-redeploy csi-logs csi-logs-registrar csi-status bpfman-build bpfman-proto bpfman-clean bpfman-docker-build bpfman-docker-build-builder bpfman-docker-clean-builder bpfman-kind-load bpfman-deploy bpfman-delete bpfman-logs bpfman-deploy-test bpfman-delete-test bpfman-test-grpc deploy-app-pod delete-app-pod delete-all

help:
	@echo "CSI Driver:"
	@echo "  csi-build          Build csi-driver binary"
	@echo "  csi-test           Run csi-driver tests"
	@echo "  csi-docker-build   Build csi-driver container image"
	@echo "  csi-deploy         Deploy csi-driver to kind cluster"
	@echo "  csi-delete         Remove csi-driver from cluster"
	@echo "  csi-logs           Follow csi-driver logs"
	@echo "  csi-status         Show csi-driver status"
	@echo ""
	@echo "bpfman:"
	@echo "  bpfman-build       Build bpfman binary"
	@echo "  bpfman-proto       Generate protobuf/gRPC stubs"
	@echo "  bpfman-clean       Remove generated files and binary"
	@echo "  bpfman-docker-build Build bpfman container image"
	@echo "  bpfman-deploy      Deploy bpfman to kind cluster"
	@echo "  bpfman-delete      Remove bpfman from cluster"
	@echo "  bpfman-logs        Follow bpfman logs"
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

# CSI Driver targets
csi-build:
	cd csi-driver && go build -o ../$(BIN_DIR)/bpffs-csi-driver .

csi-test:
	cd csi-driver && go test -v ./...

csi-docker-build:
	docker buildx build --builder=default --load -t $(IMAGE_NAME):$(IMAGE_TAG) csi-driver/

csi-kind-load: csi-docker-build
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
	@kubectl -n $(NAMESPACE) get pods -l app=bpffs-csi-node -o wide
	@echo ""
	@echo "=== CSI Drivers ==="
	@kubectl get csidrivers

# bpfman targets
bpfman-build: bpfman-proto
	cd bpfman && go build -o ../$(BIN_DIR)/bpfman ./cmd/bpfman

bpfman-clean:
	$(RM) -r bpfman/internal/server/pb/
	$(RM) $(BIN_DIR)/bpfman

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

bpfman-docker-build-builder:
	@docker image inspect $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) >/dev/null 2>&1 || \
		docker buildx build --builder=default --load -t $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) -f bpfman/Dockerfile.builder bpfman/

bpfman-docker-clean-builder:
	-docker rmi $(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG)

bpfman-docker-build: bpfman-docker-build-builder bpfman/testdata/stats.o bpfman-proto
	docker buildx build --builder=default --load --build-arg BUILDER_IMAGE=$(BPFMAN_BUILDER_IMAGE):$(IMAGE_TAG) -t $(BPFMAN_IMAGE):$(IMAGE_TAG) bpfman/

bpfman-kind-load: bpfman-docker-build
	kind load docker-image $(BPFMAN_IMAGE):$(IMAGE_TAG) --name $(KIND_CLUSTER)

bpfman-deploy: bpfman-kind-load
	kubectl apply -f deploy/bpfman.yaml
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpfman --timeout=60s

bpfman-delete:
	kubectl delete -f deploy/bpfman.yaml --ignore-not-found

bpfman-logs:
	kubectl -n $(NAMESPACE) logs -l app=bpfman -f

bpfman-deploy-test: bpfman-kind-load
	kubectl apply -f bpfman/deploy/test-pod.yaml
	kubectl wait --for=condition=Ready pod/bpfman-test --timeout=30s

bpfman-delete-test:
	kubectl delete -f bpfman/deploy/test-pod.yaml --ignore-not-found

bpfman-test-grpc: bpfman-docker-build
	BPFMAN_IMAGE=$(BPFMAN_IMAGE):$(IMAGE_TAG) bpfman/scripts/test-grpc.sh

# bpfman testdata
BPFMAN_HACKS_DIR ?= $(HOME)/src/github.com/frobware/bpfman-hacks

bpfman/testdata/stats.o: $(BPFMAN_HACKS_DIR)/stats/bpf/stats.o
	mkdir -p bpfman/testdata
	cp $< $@

# Combined targets
deploy-app-pod: csi-deploy bpfman-deploy
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpffs-csi-node --timeout=60s
	kubectl apply -f deploy/app-pod.yaml
	kubectl wait --for=condition=Ready pod/bpffs-app-pod --timeout=30s
	@echo ""
	@echo "=== Volume mount ==="
	@kubectl exec bpffs-app-pod -- mount | grep /bpf

delete-app-pod:
	kubectl delete -f deploy/app-pod.yaml --ignore-not-found

delete-all: delete-app-pod csi-delete bpfman-delete

clean: bpfman-clean
	$(RM) -r $(BIN_DIR)
