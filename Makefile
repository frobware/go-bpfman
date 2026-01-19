.PHONY: build test clean docker-build kind-load deploy-driver delete-driver redeploy logs logs-registrar status deploy-test-pod delete-test-pod

IMAGE_NAME ?= bpffs-csi-driver
IMAGE_TAG ?= dev
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
	docker buildx build --load -t $(IMAGE_NAME):$(IMAGE_TAG) .

kind-load: docker-build
	kind load docker-image $(IMAGE_NAME):$(IMAGE_TAG) --name $(KIND_CLUSTER)

deploy-driver: kind-load
	kubectl apply -f deploy/csidriver.yaml -f deploy/daemonset.yaml
	kubectl -n $(NAMESPACE) rollout restart daemonset/bpffs-csi-node

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

deploy-test-pod: deploy-driver
	kubectl -n $(NAMESPACE) wait --for=condition=Ready pod -l app=bpffs-csi-node --timeout=60s
	kubectl apply -f deploy/test-pod.yaml
	kubectl wait --for=condition=Ready pod/bpffs-test-pod --timeout=30s
	@echo ""
	@echo "=== Volume contents ==="
	@kubectl exec bpffs-test-pod -- cat /bpf/csi-volume-info.txt

delete-test-pod:
	kubectl delete -f deploy/test-pod.yaml --ignore-not-found
