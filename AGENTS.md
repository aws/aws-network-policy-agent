# AGENTS.md

Guidance for coding agents and human contributors working in this repository.

## What this is

The AWS Network Policy Agent enforces Kubernetes NetworkPolicy and ClusterNetworkPolicy on EKS nodes with eBPF. It runs on each node as a container in the `aws-node` DaemonSet.

- `main.go`: agent entry point. `controllers/`: reconcilers for PolicyEndpoint and ClusterPolicyEndpoint objects.
- `pkg/ebpf/`: loads, attaches and recovers the BPF programs through `github.com/aws/aws-ebpf-sdk-go`. `pkg/ebpf/c/`: the BPF C sources (four tc programs, two events programs, v4 and v6).
- `pkg/fwruleprocessor/`: turns policy rules into BPF map entries. `pkg/rpc/`: the gRPC server the VPC CNI calls on pod add and delete.
- `cmd/cli`, `cmd/cliv6`: the `aws-eks-na-cli` node tools. `test/`: ginkgo integration suites and framework.

## Build and test

- `make build-linux`: builds the agent and both CLIs with the host Go toolchain (version in `.go-version`).
- `make build-bpf`: compiles the BPF objects with clang. It needs `pkg/ebpf/c/vmlinux.h`, which `make vmlinuxh` generates on a Linux host with `bpftool`. `make docker-build` builds the image, including the objects.
- `make test`: unit tests, `go test ./pkg/... ./controllers/...` with coverage. `make docker-unit-tests` runs them in the test container. For one package: `go test ./pkg/ebpf/...`.
- `make check-format` (needs `goimports`) and `make vet`: the code checks CI runs.
- `make build-test-binaries`: builds every `test/integration/<suite>` into `test/build/` (needs `ginkgo`). Suites run against a live cluster: `make run-cyclonus-test CLUSTER_NAME=<name>` runs `scripts/run-cyclonus-tests.sh`.

CI:

- `.github/workflows/pr-tests.yaml` runs on PRs to `main` and `release*`: `check-format`, `vet`, `build-linux` and `make test`, plus `make docker-buildx`. Only the docker job compiles the C.
- A PR comment `/test cyclonus <full-sha>` from a user with write access runs `pr-cyclonus-tests.yaml`: cyclonus plus the `policy`, `ebpf`, `clusternetworkpolicy` and `strict` suites, on IPv4 and IPv6 clusters.
- `nightly-kernel-tests.yaml` runs `scripts/run-kernel-smoke-tests.sh` (`policy`, then `strict`) daily across AL2023 kernel lines. New eBPF tests belong there too.
- `restart`, `leak`, `upgrade` and `soak` are not run by any workflow. Verifier rejections show up only on a real kernel.

## Hard rules

- **v4/v6 parity.** A datapath change goes into both families: the C programs, conntrack GC, event decoding, CLI and tests. Run `python3 -I hack/v4v6-diff.py --all .` at the merge base and at the change; the change should add no hunk unless it is family-specific by design.
- **SDK naming.** The SDK splits pin names at the first `_`. A `LoadBpfFile*` prefix must not contain `_`. Every per-pod map must be listed in `utils.NamespacedBPFMaps`, or it is treated as a global map.
- **Flags.** Treat a new agent flag as a one-way door. Prefer no flag. For a test-only code path, use a test-only mechanism such as the test agent image, not a product flag.
- **BPF object bytes.** Any edit to a `pkg/ebpf/c` file changes the object's bytes, and every node reloads that object on upgrade. When both directions must reload, bump `NPA_FILE_VERSION` in all four tc programs.
- **Headers.** `.gitignore` ignores `*.h`. A new header in `pkg/ebpf/c/` needs an exception.
- **Cached objects.** The reconcilers read with `client.UnsafeDisableDeepCopy`. Never write to those objects or to anything reachable from them.
- **Locks.** `podIdentifierLocks` is not re-entrant. Helpers that expect it held end in `Locked`.
- **Logging.** Use the package's `log()` helper. The logger formats like `fmt.Sprintf`, so use `%v`, not `%w`.
- **Comments.** Describe current behavior and why, not change history.

## Review checklist

`docs/review-guide.md` has the full checklist: SDK contracts, v4/v6 parity, upgrade and rollback, precedents to reuse, and recurring review themes, each with code citations and a way to check it. Read the sections that match the files a change touches before you open or review a PR.
