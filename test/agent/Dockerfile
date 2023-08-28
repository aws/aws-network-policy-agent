FROM public.ecr.aws/eks-distro-build-tooling/golang:1.20.6-7-gcc-al2 as builder

WORKDIR /workspace
ENV GOPROXY direct

COPY go.mod go.mod

COPY go.sum go.sum

RUN go mod download

COPY cmd cmd

# Package all testing binaries into one docker file
# which can be used for different test scenarios
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build \
    -a -o check-bpf-cleanup-client cmd/check-bpf-cleanup-client/main.go

FROM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-iptables:latest.2

WORKDIR /
COPY --from=builder /workspace/ .
