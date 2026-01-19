.PHONY: build test clean docker-build kind-load deploy-driver delete-driver redeploy logs logs-registrar status deploy-app-pod delete-app-pod delete-all docker-build-bpfman-lite kind-load-bpfman-lite deploy-bpfman-lite delete-bpfman-lite logs-bpfman-lite docker-build-bpfman-builder docker-build-bpfman kind-load-bpfman deploy-bpfman-test delete-bpfman-test

IMAGE_NAME ?= bpffs-csi-driver
IMAGE_TAG ?= dev
BPFMAN_LITE_IMAGE ?= bpfman-lite
BPFMAN_BUILDER_IMAGE ?= bpfman-builder
BPFMAN_IMAGE ?= bpfman
KIND_CLUSTER ?= bpfman-deployment
NAMESPACE ?= kube-system
BINARY_NAME ?= bpffs-csi-driver

build:
	cd csi-driver && go build -o $(BINARY_NAME) .

test:
	cd csi-driver && go test -v ./...

clean:
	rm -f csi-driver/$(BINARY_NAME)

docker-build:
	docker buildx build --quiet --load -t $(IMAGE_NAME):$(IMAGE_TAG) csi-driver/

kind-load: docker-build
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

docker-build-bpfman-lite:
	docker buildx build --quiet --load -t $(BPFMAN_LITE_IMAGE):$(IMAGE_TAG) bpfman-lite/

kind-load-bpfman-lite: docker-build-bpfman-lite
	kind load docker-image $(BPFMAN_LITE_IMAGE):$(IMAGE_TAG) --name $(KIND_CLUSTER)

deploy-bpfman-lite: kind-load-bpfman-lite
	kubectl apply -f deploy/bpfman-lite.yaml
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpfman-lite --timeout=60s

delete-bpfman-lite:
	kubectl delete -f deploy/bpfman-lite.yaml --ignore-not-found

logs-bpfman-lite:
	kubectl -n $(NAMESPACE) logs -l app=bpfman-lite -f

deploy-app-pod: deploy-driver deploy-bpfman-lite
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpffs-csi-node --timeout=60s
	kubectl apply -f deploy/app-pod.yaml
	kubectl wait --for=condition=Ready pod/bpffs-app-pod --timeout=30s
	@echo ""
	@echo "=== Volume mount ==="
	@kubectl exec bpffs-app-pod -- mount | grep /bpf

delete-app-pod:
	kubectl delete -f deploy/app-pod.yaml --ignore-not-found

delete-all: delete-app-pod delete-driver delete-bpfman-lite

# bpfman targets
BPFMAN_HACKS_DIR ?= $(HOME)/src/github.com/frobware/bpfman-hacks

bpfman/testdata/stats.o: $(BPFMAN_HACKS_DIR)/stats/bpf/stats.o
	mkdir -p bpfman/testdata
	cp $< $@

docker-build-bpfman-builder:
	docker build -t $(BPFMAN_BUILDER_IMAGE):latest -f bpfman/Dockerfile.builder bpfman/

docker-build-bpfman: bpfman/testdata/stats.o
	docker build -t $(BPFMAN_IMAGE):$(IMAGE_TAG) bpfman/

kind-load-bpfman: docker-build-bpfman
	kind load docker-image $(BPFMAN_IMAGE):$(IMAGE_TAG) --name $(KIND_CLUSTER)

deploy-bpfman-test: kind-load-bpfman
	kubectl apply -f bpfman/deploy/test-pod.yaml
	kubectl wait --for=condition=Ready pod/bpfman-test --timeout=30s

delete-bpfman-test:
	kubectl delete -f bpfman/deploy/test-pod.yaml --ignore-not-found
