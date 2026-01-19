.PHONY: build test clean docker-build kind-load deploy undeploy redeploy logs logs-registrar status

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
	docker buildx build \
		--load \
		--cache-from type=local,src=.buildx-cache \
		--cache-to type=local,dest=.buildx-cache,mode=max \
		-t $(IMAGE_NAME):$(IMAGE_TAG) .

kind-load: docker-build
	kind load docker-image $(IMAGE_NAME):$(IMAGE_TAG) --name $(KIND_CLUSTER)

deploy:
	kubectl apply -f deploy/

undeploy:
	kubectl delete -f deploy/ --ignore-not-found

redeploy: kind-load undeploy deploy

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
