ARG golang_image

FROM $golang_image AS builder

WORKDIR /workspace
ENV GOPROXY direct

COPY go.mod go.mod

COPY go.sum go.sum

RUN go mod download

COPY cmd cmd

# Package all testing binaries into one docker file
# which can be used for different test scenarios
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build \
    -a -o check-bpf-cleanup-agent cmd/check-bpf-cleanup-agent/main.go

FROM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-iptables:latest.2

WORKDIR /
COPY --from=builder /workspace/ .
