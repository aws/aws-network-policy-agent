
# Image URL to use all building/pushing image targets
IMAGE ?= amazon/aws-network-policy-agent
VERSION ?= $(shell git describe --tags --always --dirty || echo "unknown")
IMAGE_NAME = $(IMAGE)$(IMAGE_ARCH_SUFFIX):$(VERSION)
GOLANG_VERSION ?= $(shell cat .go-version)
GOLANG_IMAGE ?= public.ecr.aws/eks-distro-build-tooling/golang:$(GOLANG_VERSION)-gcc-al2
# TEST_IMAGE is the testing environment container image.
TEST_IMAGE = aws-network-policy-agent-test
TEST_IMAGE_NAME = $(TEST_IMAGE)$(IMAGE_ARCH_SUFFIX):$(VERSION)
MAKEFILE_PATH = $(dir $(realpath -s $(firstword $(MAKEFILE_LIST))))

export GOPROXY = direct
export GOSUMDB = sum.golang.org

# aws-ebpf-sdk-go override in case we need to build against a custom version
EBPF_SDK_OVERRIDE ?= "n"

ifeq ($(EBPF_SDK_OVERRIDE), "y")
VENDOR_OVERRIDE_FLAG = -mod=mod
endif

UNAME_ARCH = $(shell uname -m)
ARCH = $(lastword $(subst :, ,$(filter $(UNAME_ARCH):%,x86_64:amd64 aarch64:arm64)))
# This is only applied to the arm64 container image by default. Override to
# provide an alternate suffix or to omit.
IMAGE_ARCH_SUFFIX = $(addprefix -,$(filter $(ARCH),arm64))

# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.25.0

# Skip installing the latest managed addon while running cyclonus test
SKIP_ADDON_INSTALLATION ?= "false"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: setup-ebpf-sdk-override # Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./cmd/... ./controllers/... ./pkg/... -coverprofile cover.out -v -coverprofile=coverage.txt

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./main.go

GO_ENV_EBPF =
GO_ENV_EBPF += CGO_ENABLED=1
GO_ENV_EBPF += GOOS=linux
GO_ENV_EBPF += GOARCH=$(GO_ARCH)
GO_ENV_EBPF += CGO_CFLAGS=$(CUSTOM_CGO_CFLAGS)
GO_ENV_EBPF += CGO_LDFLAGS=$(CUSTOM_CGO_LDFLAGS)

# Build using the host's Go toolchain.
BUILD_MODE ?= -buildmode=pie
build-linux: BUILD_FLAGS = $(BUILD_MODE) -ldflags '-s -w $(LDFLAGS) -extldflags "-static"'
build-linux: ## Build the controllerusing the host's Go toolchain.
	$(GO_ENV_EBPF) go build $(VENDOR_OVERRIDE_FLAG) $(BUILD_FLAGS) -tags netgo,ebpf,core -a -o controller main.go
	go build $(VENDOR_OVERRIDE_FLAG) $(BUILD_FLAGS) -o aws-eks-na-cli ./cmd/cli
	go build $(VENDOR_OVERRIDE_FLAG) $(BUILD_FLAGS) -o aws-eks-na-cli-v6 ./cmd/cliv6


CMD_MKDIR ?= mkdir
CMD_CLANG ?= clang
CMD_GIT ?= git
CMD_RM ?= rm


EBPF_DIR = ./pkg/ebpf/c
EBPF_OBJ_CORE_HEADERS = $(shell find pkg/ebpf/c -name *.h)
EBPF_OBJ_SRC = ./pkg/ebpf/c/xdpdrop.bpf.c
EBPF_OBJ_SRC_TC = ./pkg/ebpf/c/tc.bpf.c

vmlinuxh:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(abspath ./$(EBPF_DIR))/vmlinux.h

ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

BPF_VCPU = v2
# Build BPF
CLANG_INCLUDE := -I../../.
EBPF_SOURCE_INGRESS_TC := ./pkg/ebpf/c/tc.v4ingress.bpf.c
EBPF_BINARY_INGRESS_TC := ./pkg/ebpf/c/tc.v4ingress.bpf.o
EBPF_SOURCE_EGRESS_TC := ./pkg/ebpf/c/tc.v4egress.bpf.c
EBPF_BINARY_EGRESS_TC := ./pkg/ebpf/c/tc.v4egress.bpf.o
EBPF_SOURCE_V6_INGRESS_TC := ./pkg/ebpf/c/tc.v6ingress.bpf.c
EBPF_BINARY_V6_INGRESS_TC := ./pkg/ebpf/c/tc.v6ingress.bpf.o
EBPF_SOURCE_V6_EGRESS_TC := ./pkg/ebpf/c/tc.v6egress.bpf.c
EBPF_BINARY_V6_EGRESS_TC := ./pkg/ebpf/c/tc.v6egress.bpf.o
EBPF_EVENTS_SOURCE_TC := ./pkg/ebpf/c/v4events.bpf.c
EBPF_EVENTS_BINARY_TC := ./pkg/ebpf/c/v4events.bpf.o
EBPF_V6_EVENTS_SOURCE_TC := ./pkg/ebpf/c/v6events.bpf.c
EBPF_V6_EVENTS_BINARY_TC := ./pkg/ebpf/c/v6events.bpf.o

build-bpf: ## Build BPF.
	$(CMD_CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_x86 -c $(EBPF_EVENTS_SOURCE_TC) -o $(EBPF_EVENTS_BINARY_TC)
	$(CMD_CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_x86 -c $(EBPF_V6_EVENTS_SOURCE_TC) -o $(EBPF_V6_EVENTS_BINARY_TC)
	$(CMD_CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_SOURCE_INGRESS_TC) -o $(EBPF_BINARY_INGRESS_TC)
	$(CMD_CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_SOURCE_EGRESS_TC) -o $(EBPF_BINARY_EGRESS_TC)
	$(CMD_CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_SOURCE_V6_INGRESS_TC) -o $(EBPF_BINARY_V6_INGRESS_TC)
	$(CMD_CLANG) $(CLANG_INCLUDE) -g -O2 -Wall -fpie -target bpf -DCORE -D__BPF_TRACING__ -march=bpf -D__TARGET_ARCH_$(ARCH) -c $(EBPF_SOURCE_V6_EGRESS_TC) -o $(EBPF_BINARY_V6_EGRESS_TC)

# If you wish built the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64 ). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
#docker-build: test ## Build docker image with the manager.
#	docker build -t ${IMAGE_NAME} .
docker-build: setup-ebpf-sdk-override## Build docker image with the manager.
	docker build -t ${IMAGE_NAME} --build-arg golang_image="$(GOLANG_IMAGE)" .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${IMAGE_NAME}

##@ Build and Run Unit Tests
# Build the unit test driver container image.
build-docker-test:     ## Build the unit test driver container image.
	docker build $(DOCKER_BUILD_FLAGS_NP_AGENT) \
		-f Dockerfile.test \
		-t $(TEST_IMAGE_NAME) \
		--build-arg golang_image="$(GOLANG_IMAGE)" \
		.

# Run unit tests inside of the testing container image.
docker-unit-tests: build-docker-test     ## Run unit tests inside of the testing container image.
	docker run $(DOCKER_RUN_ARGS) \
		$(TEST_IMAGE_NAME) \
		make test


# PLATFORMS defines the target platforms for  the manager image be build to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - able to use docker buildx . More info: https://docs.docker.com/build/buildx/
# - have enable BuildKit, More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image for your registry (i.e. if you do not inform a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To properly provided solutions that supports more than one platform you should use this option.
PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx: setup-ebpf-sdk-override ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- docker buildx create --name project-v3-builder
	docker buildx use project-v3-builder
	docker buildx build $(DOCKER_BUILD_FLAGS_NP_AGENT) \
		-f Dockerfile.cross \
		--platform "$(PLATFORMS)"\
		--cache-from=type=gha \
		--cache-to=type=gha,mode=max \
		--build-arg golang_image="$(GOLANG_IMAGE)" \
		.
	- docker buildx rm project-v3-builder
	rm Dockerfile.cross


.PHONY: multi-arch-build-and-push
multi-arch-build-and-push: setup-ebpf-sdk-override ## Build and push docker image for the manager for cross-platform support

	docker buildx build $(DOCKER_BUILD_FLAGS_NP_AGENT) \
		-f Dockerfile \
		--platform "$(PLATFORMS)"\
		--cache-from=type=gha \
		--cache-to=type=gha,mode=max \
		-t $(IMAGE):$(VERSION) \
		--build-arg golang_image="$(GOLANG_IMAGE)" \
		--push \
		.

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest

## Tool Versions
KUSTOMIZE_VERSION ?= v5.4.3
CONTROLLER_TOOLS_VERSION ?= v0.16.3

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary. If wrong version is installed, it will be removed before downloading.
$(KUSTOMIZE): $(LOCALBIN)
	@if test -x $(LOCALBIN)/kustomize && ! $(LOCALBIN)/kustomize version | grep -q $(KUSTOMIZE_VERSION); then \
		echo "$(LOCALBIN)/kustomize version is not expected $(KUSTOMIZE_VERSION). Removing it before installing."; \
		rm -rf $(LOCALBIN)/kustomize; \
	fi
	test -s $(LOCALBIN)/kustomize || { curl -Ss $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN); }

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.0.0-20230216140739-c98506dc3b8e

# Check formatting of source code files without modification.
check-format: FORMAT_FLAGS = -l
check-format: format

format:       ## Format all Go source code files.
	@command -v goimports >/dev/null || { echo "ERROR: goimports not installed"; exit 1; }
	@exit $(shell find ./* \
	  -type f \
	  -name '*.go' \
	  -print0 | sort -z | xargs -0 -- goimports $(or $(FORMAT_FLAGS),-w) | wc -l | bc)

setup-ebpf-sdk-override:
	@if [ "$(EBPF_SDK_OVERRIDE)" = "y" ] ; then \
	    ./scripts/ebpf_sdk_override/setup.sh ; \
	fi

cleanup-ebpf-sdk-override:
	@if [ "$(EBPF_SDK_OVERRIDE)" = "y" ] ; then \
	    ./scripts/ebpf_sdk_override/cleanup.sh ; \
	fi

.PHONY: run-cyclonus-test
run-cyclonus-test: ## Runs cyclonus tests on an existing cluster. Call with CLUSTER_NAME=<name of your cluster>, SKIP_ADDON_INSTALLATION=<true/false> to execute cyclonus test
ifdef CLUSTER_NAME
	CLUSTER_NAME=$(CLUSTER_NAME) SKIP_ADDON_INSTALLATION=$(SKIP_ADDON_INSTALLATION) ./scripts/run-cyclonus-tests.sh
else
	@echo 'Pass CLUSTER_NAME parameter'
endif

./PHONY: update-node-agent-image
update-node-agent-image: ## Updates node agent image on an existing cluster. Optionally call with AWS_EKS_NODEAGENT=<Image URI>
	./scripts/update-node-agent-image.sh AWS_EKS_NODEAGENT=$(AWS_EKS_NODEAGENT) IP_FAMILY=$(IP_FAMILY)

./PHONY: update-image-and-test
update-image-and-test: ## Updates node agent image on existing cluster and runs cyclonus tests. Call with CLUSTER_NAME=<name of the cluster> and AWS_EKS_NODEAGENT=<Image URI>
	$(MAKE) update-node-agent-image AWS_EKS_NODEAGENT=$(AWS_EKS_NODEAGENT)
	$(MAKE) run-cyclonus-test CLUSTER_NAME=$(CLUSTER_NAME) SKIP_ADDON_INSTALLATION=true

./PHONY: deploy-network-policy-controller-on-dataplane
deploy-network-policy-controller-on-dataplane: ## This uses the script from amazon-network-policy-controller-k8s repository to install the controller on dataplane nodes
	@if [ ! -d ./amazon-network-policy-controller-k8s ]; then \
		git clone https://github.com/aws/amazon-network-policy-controller-k8s.git; \
	fi
	./amazon-network-policy-controller-k8s/scripts/deploy-controller-on-dataplane.sh NP_CONTROLLER_IMAGE=$(NP_CONTROLLER_IMAGE) NP_CONTROLLER_ENDPOINT_CHUNK_SIZE=$(NP_CONTROLLER_ENDPOINT_CHUNK_SIZE)

clean: # Clean temporary files and build artifacts from the project
	@rm -f -- aws-eks-na-cli
	@rm -f -- aws-eks-na-cli-v6
	@rm -f -- coverage.txt

build-test-binaries: # Builds the test suite binaries
	mkdir -p ${MAKEFILE_PATH}test/build
	cd ${MAKEFILE_PATH} && \
	find ${MAKEFILE_PATH}test -name '*suite_test.go' -type f  | xargs dirname  | xargs ginkgo build
	find ${MAKEFILE_PATH}test -name "*.test" -print0 | xargs -0 -I {} mv {} ${MAKEFILE_PATH}test/build
