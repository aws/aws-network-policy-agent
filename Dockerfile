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

RUN make build-linux

# Build BPF
FROM public.ecr.aws/amazonlinux/amazonlinux:2 as bpfbuilder
WORKDIR /bpfbuilder
RUN yum update -y && \
    yum install -y iproute procps-ng && \
    yum install -y llvm clang make gcc && \
    yum install -y coreutils kernel-devel elfutils-libelf-devel zlib-devel bpftool libbpf-devel && \
    yum clean all

COPY . ./
RUN make build-bpf

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
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/events.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/v6events.bpf.o .

ENTRYPOINT ["/controller"]
