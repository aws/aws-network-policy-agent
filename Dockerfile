# Build the manager binary
FROM golang:1.19 as builder
ARG TARGETOS
ARG TARGETARCH

# Env configuration
ENV GOPROXY=direct

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# For EBPF
RUN apt-get update && \
    apt-get install -y llvm clang make gcc && \
    apt-get install -y libelf-dev && \
    apt-get install -y zlib1g-dev

COPY . ./
# Copy the go source
#COPY main.go main.go
#COPY api/ api/
#COPY pkg/ pkg/
#COPY controllers/ controllers/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
#RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o manager main.go

RUN make build-linux

# Build BPF
FROM public.ecr.aws/amazonlinux/amazonlinux:2 as bpfbuilder
WORKDIR /bpfbuilder
RUN yum update -y && \
    yum install -y iproute procps-ng && \
    yum install -y llvm clang make gcc && \
    yum install -y coreutils kernel-devel elfutils-libelf-devel zlib-devel bpftool libbpf-devel && \
    yum clean all

COPY Makefile ./
COPY . ./
RUN make build-bpf

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
#FROM gcr.io/distroless/static:nonroot
#WORKDIR /
#COPY --from=builder /workspace/manager .
#USER 65532:65532
FROM public.ecr.aws/amazonlinux/amazonlinux:2
RUN yum update -y && \
    yum install -y iptables iproute jq && \
    yum install -y llvm clang make gcc && \
    yum install -y coreutils kernel-devel elfutils-libelf-devel zlib-devel bpftool libbpf-devel && \
    yum clean all

WORKDIR /
COPY --from=builder /workspace/controller .
COPY --from=builder /workspace/aws-eks-na-cli .
COPY --from=builder /workspace/aws-eks-na-cli-v6 .
#COPY --from=builder /workspace/cmd .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/events.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/v6events.bpf.o .
#USER 65532:65532

ENTRYPOINT ["/controller"]
#ENTRYPOINT ["/manager"]
