.PHONY: build test clean docker-build kind-load deploy-driver delete-driver redeploy logs logs-registrar status deploy-app-pod delete-app-pod delete-all docker-build-bpfman-lite kind-load-bpfman-lite deploy-bpfman-lite delete-bpfman-lite logs-bpfman-lite

IMAGE_NAME ?= bpffs-csi-driver
IMAGE_TAG ?= dev
BPFMAN_LITE_IMAGE ?= bpfman-lite
KIND_CLUSTER ?= bpfman-deployment
NAMESPACE ?= kube-system
BINARY_NAME ?= bpffs-csi-driver

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
