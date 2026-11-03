# AGENTS.md

Guidance for coding agents and human contributors working in this repository.

## What this is

The AWS Network Policy Agent enforces Kubernetes NetworkPolicy and ClusterNetworkPolicy on EKS nodes with eBPF. It runs on each node as a container in the `aws-node` DaemonSet.

- `main.go`: agent entry point. `controllers/`: reconcilers for PolicyEndpoint and ClusterPolicyEndpoint objects.
- `pkg/ebpf/`: loads, attaches and recovers the BPF programs through `github.com/aws/aws-ebpf-sdk-go`. `pkg/ebpf/c/`: the BPF C sources, four tc programs and two events programs, v4 and v6. The two ingress sources are also built with `-DNPA_CT_SHORTEN_ON_DENY` into the ct-deny objects (code in `ct_deny.h`), so the image ships six tc objects and two events objects. The agent picks the ct-deny or the regular ingress object once at startup.
- `pkg/fwruleprocessor/`: turns policy rules into BPF map entries. `pkg/rpc/`: the gRPC server the VPC CNI calls on pod add and delete.
- `cmd/cli`, `cmd/cliv6`: the `aws-eks-na-cli` node tools. `test/`: ginkgo integration suites and framework.

## Build and test

- `make build-linux`: builds the agent and both CLIs with the host Go toolchain (Go 1.26.9 or later, per `go.mod`; `.go-version` picks the Go image for docker builds).
- `make build-bpf`: compiles the BPF objects with clang. It needs `pkg/ebpf/c/vmlinux.h`, which `make vmlinuxh` generates on a Linux host with `bpftool`. `make docker-build` builds the image, including the objects.
- `make test`: unit tests, `go test ./pkg/... ./controllers/...` with coverage. `make docker-unit-tests` runs them in the test container. For one package: `go test ./pkg/ebpf/...`.
- `make check-format` (needs `goimports`) and `make vet`: the code checks CI runs.
- `make build-test-binaries`: builds every `test/integration/<suite>` except `soak` into `test/build/` (needs `ginkgo`). Suites run against a live cluster: `make run-cyclonus-test CLUSTER_NAME=<name>` runs `scripts/run-cyclonus-tests.sh`.

CI:

- `.github/workflows/pr-tests.yaml` runs on pushes to `main` and on PRs to `main` and `release*`: `check-format`, `vet`, `build-linux` and `make test`. On PRs it also runs `make docker-buildx`, a deprecated-apiGroups check and `govulncheck`. Only the docker job compiles the C.
- A PR comment `/test cyclonus <full-sha>` from a user with write access runs `pr-cyclonus-tests.yaml`: cyclonus plus the `policy`, `ebpf`, `clusternetworkpolicy` and `strict` suites, on IPv4 and IPv6 clusters.
- `nightly-kernel-tests.yaml` runs `scripts/run-kernel-smoke-tests.sh` (`policy`, `ebpf`, then `strict`) daily across AL2023 kernel lines, on IPv4 and IPv6. New eBPF tests belong in one of those suites.
- `restart`, `leak`, `upgrade` and `soak` are not run by any workflow. Verifier rejections show up only on a real kernel.

## Hard rules

- **v4/v6 parity.** A datapath change goes into both families: the C programs (including the `NPA_CT_SHORTEN_ON_DENY` blocks and `ct_deny.h`), conntrack GC, event decoding, CLI and tests. Run `python3 -I hack/v4v6-diff.py --all .` at the merge base and at the change; it diffs both ingress builds. The change should add no hunk unless it is family-specific by design.
- **SDK naming.** The SDK splits pin names at the first `_`. A `LoadBpfFile*` prefix must not contain `_`. Every per-pod map must be listed in `utils.NamespacedBPFMaps`, or it is treated as a global map.
- **Flags.** Treat a new agent flag as a one-way door. Prefer no flag. For a test-only code path, use a test-only mechanism (for example a test binary or image under `test/`), not a product flag.
- **BPF object bytes.** An edit to a `pkg/ebpf/c` file that changes code or shifts line numbers changes the bytes of every object built from it, even if it only adds a comment line: the objects are built with `-g`, so `.BTF.ext`, `.debug_info` and `.debug_line` change. Every node reloads a changed object on upgrade. A comment reworded in place, or appended at the end of a file, left the objects byte-identical (clang 15.0.7 on AL2023). Treat any edit as changing the bytes unless you have built both versions and compared them. When both directions must reload, bump `NPA_FILE_VERSION` in all four tc programs.
- **Headers.** `.gitignore` ignores `*.h`. A new header in `pkg/ebpf/c/` needs an exception, as `ct_deny.h` has.
- **Cached objects.** The reconcilers read with `client.UnsafeDisableDeepCopy`. Never write to those objects or to anything reachable from them.
- **Locks.** `podIdentifierLocks` is not re-entrant: never take it in a function called with it held. Some such helpers end in `Locked`, but the attach, load and delete helpers (`attachIngressBPFProbe`, `loadBPFProgram`, `deleteBPFProbes`) also run under it without the suffix.
- **Logging.** Use the package's `log()` helper. The logger formats like `fmt.Sprintf`, so use `%v`, not `%w`.
- **Comments.** Describe current behavior and why, not change history.

## Review checklist

`docs/review-guide.md` has the full checklist: SDK contracts, v4/v6 parity, upgrade and rollback, precedents to reuse, and recurring review themes, each with code citations and a way to check it. Read the sections that match the files a change touches before you open or review a PR. Each item is tagged `[blocking]` or `[advisory]`. When reviewing, report a finding as blocking only when its own impact meets the blocking bar in the guide's section 1, not because the guide item is tagged blocking; list blocking findings first and keep advisory ones brief.

[`docs/using-the-review-guide.md`](docs/using-the-review-guide.md) explains how to use AGENTS.md, the review guide and the diff helper in your workflow.
