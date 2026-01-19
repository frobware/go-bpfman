.PHONY: build test clean docker-build-csi kind-load deploy-driver delete-driver redeploy logs logs-registrar status deploy-app-pod delete-app-pod delete-all docker-build-bpfman docker-build-bpfman-builder kind-load-bpfman deploy-bpfman delete-bpfman logs-bpfman deploy-bpfman-test delete-bpfman-test

IMAGE_NAME ?= bpffs-csi-driver
IMAGE_TAG ?= dev
BPFMAN_IMAGE ?= bpfman
BPFMAN_BUILDER_IMAGE ?= bpfman-builder
KIND_CLUSTER ?= bpfman-deployment
NAMESPACE ?= kube-system
BINARY_NAME ?= bpffs-csi-driver

build:
	cd csi-driver && go build -o $(BINARY_NAME) .

test:
	cd csi-driver && go test -v ./...

clean:
	rm -f csi-driver/$(BINARY_NAME)

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

docker-build-bpfman: docker-build-bpfman-builder bpfman/testdata/stats.o
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
