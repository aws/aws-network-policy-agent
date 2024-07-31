# Build the manager binary
ARG golang_image=golang:1.22.4

FROM $golang_image as builder

ARG TARGETOS
ARG TARGETARCH
ARG GIT_USER
ARG GIT_PAT

# Env configuration
ENV GOPROXY=direct

WORKDIR /workspace

COPY go.mod go.sum ./
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download


COPY . ./

RUN make build-linux

# Vmlinux
FROM public.ecr.aws/amazonlinux/amazonlinux:2023 as vmlinuxbuilder
WORKDIR /vmlinuxbuilder
RUN yum update -y && \
    yum install -y iproute procps-ng && \
    yum install -y llvm clang make gcc && \
    yum install -y kernel-devel elfutils-libelf-devel zlib-devel libbpf-devel bpftool && \
    yum clean all
COPY . ./
RUN make vmlinuxh

# Build BPF
FROM public.ecr.aws/amazonlinux/amazonlinux:2 as bpfbuilder
WORKDIR /bpfbuilder
RUN yum update -y && \
    yum install -y iproute procps-ng && \
    yum install -y llvm clang make gcc && \
    yum install -y kernel-devel elfutils-libelf-devel zlib-devel libbpf-devel && \
    yum clean all

COPY . ./
COPY --from=vmlinuxbuilder /vmlinuxbuilder/pkg/ebpf/c/vmlinux.h ./pkg/ebpf/c/
RUN make build-bpf

# Container base image
FROM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-glibc:latest.2

WORKDIR /
COPY --from=builder /workspace/controller .
COPY --from=builder /workspace/aws-eks-na-cli .
COPY --from=builder /workspace/aws-eks-na-cli-v6 .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v4ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v4egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6ingress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/tc.v6egress.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/v4events.bpf.o .
COPY --from=bpfbuilder /bpfbuilder/pkg/ebpf/c/v6events.bpf.o .

ENTRYPOINT ["/controller"]
