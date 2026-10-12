# Nightly EKS kernel tests

`run.sh` discovers all Kubernetes versions in standard or extended EKS support,
reads each latest AL2023 x86_64 standard AMI from public SSM parameters, and
selects the lowest Kubernetes version for every unique kernel line. Kernel
versions come from the `awslabs/amazon-eks-ami` release notes (fetched via the
GitHub Releases API): no AWS API or docs page exposes per-AMI kernel versions —
the [EKS docs](https://docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html)
designate the GitHub release notes as the source for this information.

```bash
AWS_REGION=us-west-2 ./scripts/smoke/eks-kernel-matrix/run.sh
```

The script is read-only and prints a JSON matrix containing the Kubernetes
version, AMI ID, kernel line, and exact kernel package. `test.sh` validates the
discovery and deduplication logic without AWS credentials.

`.github/workflows/nightly-kernel-tests.yaml` runs nightly at 07:00 UTC and
through manual dispatch. It builds the default-branch image, creates one cluster
for every selected kernel and IP family, verifies the AMI and exact kernel on
all nodes, and runs `scripts/run-kernel-smoke-tests.sh` — the kernel-sensitive
suites that behave identically on IPv4 and IPv6 (`policy.test` and
`strict.test`). Upstream Cyclonus conformance
already runs nightly in `e2e-conformance.yaml` and per change in the PR bot, so
it is intentionally not repeated per kernel. Clusters are deleted in separate
retrying cleanup jobs.

Both the PR bot and nightly workflow use `scripts/eks-test-cluster.sh` for
cluster creation, addon/image setup, verification, and retrying deletion.
