.PHONY: build test clean docker-build kind-load deploy-driver delete-driver redeploy logs logs-registrar status deploy-test-pod delete-test-pod delete-all kind-install-bpftool setup-bpf-test create-test-map

IMAGE_NAME ?= bpffs-csi-driver
IMAGE_TAG ?= dev
KIND_CLUSTER ?= bpfman-deployment
KIND_NODE ?= $(KIND_CLUSTER)-control-plane
NAMESPACE ?= kube-system
BINARY_NAME ?= bpffs-csi-driver
BPF_TEST_PATH ?= /sys/fs/bpf/test

build:
	go build -o $(BINARY_NAME) .

test:
	go test -v ./...

clean:
	rm -f $(BINARY_NAME)

docker-build:
	docker buildx build --quiet --load -t $(IMAGE_NAME):$(IMAGE_TAG) .

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

kind-install-bpftool:
	docker exec $(KIND_NODE) apt-get update -qq
	docker exec $(KIND_NODE) apt-get install -y -qq bpftool

setup-bpf-test:
	docker exec $(KIND_NODE) mkdir -p $(BPF_TEST_PATH)

create-test-map: setup-bpf-test
	docker exec $(KIND_NODE) bpftool map create $(BPF_TEST_PATH)/mymap type hash key 4 value 4 entries 16 name testmap 2>/dev/null || true

deploy-test-pod: deploy-driver setup-bpf-test
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpffs-csi-node --timeout=60s
	kubectl apply -f deploy/test-pod.yaml
	kubectl wait --for=condition=Ready pod/bpffs-test-pod --timeout=30s
	@echo ""
	@echo "=== Volume mount ==="
	@kubectl exec bpffs-test-pod -- mount | grep /bpf

delete-test-pod:
	kubectl delete -f deploy/test-pod.yaml --ignore-not-found

delete-all: delete-test-pod delete-driver
