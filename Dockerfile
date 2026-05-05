# SecurityScarlet Runtime — Multi-stage Dockerfile
# Stage 1: Build eBPF C programs
# Stage 2: Build Go binary
# Stage 3: Distroless runtime image

# ── Stage 1: eBPF compilation ─────────────────────────────────────────
FROM alpine:3.19 AS ebpf-builder

RUN apk add --no-cache clang llvm linux-headers elfutils-dev

WORKDIR /build

COPY pkg/ebpf/include/ ./include/
COPY pkg/ebpf/probes/ ./probes/

# Compile each eBPF probe category
RUN for prog in process file network escape; do \
      clang -O2 -g -target bpf \
        -D__TARGET_ARCH_x86 \
        -I./include \
        -c probes/${prog}.bpf.c \
        -o ${prog}.o; \
    done

# ── Stage 2: Go binary ────────────────────────────────────────────────
FROM golang:1.22-alpine AS go-builder

RUN apk add --no-cache git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Copy compiled eBPF objects
COPY --from=ebpf-builder /build/*.o /opt/scarlet/bpf/

# Build the CLI
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -ldflags "-s -w \
      -X github.com/securityscarlet/runtime/pkg/cli.Version=${VERSION} \
      -X github.com/securityscarlet/runtime/pkg/cli.Commit=${COMMIT} \
      -X github.com/securityscarlet/runtime/pkg/cli.BuildTime=${BUILD_TIME}" \
    -o /build/scarletctl ./cmd/scarletctl/

# ── Stage 3: Runtime (distroless for security) ──────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

# Note: eBPF requires capabilities, so we run as root but with specific caps
# The distroless image has no shell — intentional per SRD Section 15.1
USER root

WORKDIR /

# Copy binary
COPY --from=go-builder /build/scarletctl /usr/bin/scarletctl

# Copy eBPF objects
COPY --from=ebpf-builder /build/*.o /opt/scarlet/bpf/

# Copy default rules
COPY rules/default_rules.yaml /etc/scarlet/rules.d/default_rules.yaml

# Copy configuration
COPY configs/scarlet-config.yaml /etc/scarlet/config.yaml

# Create log directory
# (In K8s, this is a hostPath mount, but providing a default)
# distroless doesn't have mkdir, so we rely on the entrypoint or K8s mounts

ENTRYPOINT ["scarletctl"]
CMD ["start", "--config", "/etc/scarlet/config.yaml"]