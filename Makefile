# SecurityScarlet Runtime — Container Runtime Security
# Makefile for building, testing, and deploying

BINARY_NAME   := scarletctl
BUILD_DIR     := build
GO            := go
GOFLAGS       := -trimpath -ldflags "-s -w"
VERSION       := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0-dev")
BUILD_TIME    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT        := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LD_FLAGS      := -X github.com/securityscarlet/runtime/pkg/cli.Version=$(VERSION) \
                  -X github.com/securityscarlet/runtime/pkg/cli.BuildTime=$(BUILD_TIME) \
                  -X github.com/securityscarlet/runtime/pkg/cli.Commit=$(COMMIT)

# eBPF generation
BPF_DIR       := pkg/ebpf/probes
BPF_INCLUDE  := pkg/ebpf/include

.PHONY: all build clean test lint generate-ebpf deploy-helm fmt vet

## all: Build the binary and generate eBPF objects
all: generate-ebpf build

## build: Compile the Go binary
build:
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LD_FLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/scarletctl/

## generate-ebpf: Compile eBPF C programs to BPF object files (all 5 probes)
generate-ebpf:
	@echo "Generating eBPF object files..."
	@mkdir -p $(BUILD_DIR)/bpf
	@# Generate vmlinux.h from kernel BTF (requires bpftool + BTF-enabled kernel).
	@command -v bpftool >/dev/null 2>&1 \
		&& bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(BPF_INCLUDE)/vmlinux.h \
		|| echo "  Warning: bpftool/BTF unavailable — ensure $(BPF_INCLUDE)/vmlinux.h exists (BTFHub)"
	@for prog in process file network escape network_tc; do \
		echo "  Compiling $$prog.bpf.c..."; \
		clang -O2 -g -target bpf \
			-D__TARGET_ARCH_x86 \
			-I$(BPF_INCLUDE) \
			-c $(BPF_DIR)/$${prog}.bpf.c \
			-o $(BUILD_DIR)/bpf/$${prog}.o; \
	done
	@echo "eBPF generation complete."

## generate-go: Generate Go bindings from eBPF object files (requires bpf2go)
generate-go: generate-ebpf
	@echo "Generating Go bindings from eBPF objects..."
	$(GO) generate ./pkg/ebpf/...

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY_NAME)
	$(GO) clean
	@echo "Clean complete."

## test: Run unit tests
test:
	$(GO) test -v -race -coverprofile=coverage.out ./pkg/...

## test-integration: Run integration tests (requires Docker/kind)
test-integration:
	$(GO) test -v -tags=integration ./test/...

## lint: Run linters
lint:
	golangci-lint run ./...

## fmt: Format Go code
fmt:
	gofmt -w .
	$(GO) fmt ./...

## vet: Run go vet
vet:
	$(GO) vet ./...

## deploy-helm: Deploy to current Kubernetes cluster
deploy-helm:
	helm upgrade --install scarlet-runtime deploy/helm/scarlet-runtime \
		--namespace security-scarlet \
		--create-namespace \
		--set agent.image.tag=$(VERSION)

## undeploy-helm: Remove from Kubernetes cluster
undeploy-helm:
	helm uninstall scarlet-runtime --namespace security-scarlet

## docker-build: Build Docker image
docker-build: build
	docker build -t securityscarlet/runtime-agent:$(VERSION) .

## run: Run agent locally (for development)
run: build
	sudo $(BUILD_DIR)/$(BINARY_NAME) start --config configs/scarlet-config.yaml --mode audit

## help: Show this help
help:
	@echo "SecurityScarlet Runtime — Container Runtime Security"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'