# Soak tests

Long-running tests that are **intentionally excluded from the regular
integration-test cadence** (PR gating, nightly, and canary pipelines). They take
minutes-to-an-hour and validate behavior that only emerges under sustained load,
so they are run **on demand**, not on a schedule.

## Why they don't run at the cadence

Two independent gates keep them out of the automated pipelines:

1. **Build tag `//go:build soak`** — every file here carries it, so no normal
   `go test` / `ginkgo build` compiles them. A build must explicitly opt in with
   `-tags soak`.
2. **Makefile prune** — `make build-test-binaries` (the target CI uses to compile
   all suites) prunes the `*/soak/*` path, so the aggregate build never touches
   this directory. A separate `make build-soak-test-binaries` builds them with
   the tag.

Either gate alone is sufficient; together they make it impossible for a soak test
to slip into the cadence by accident.

## Running a soak test

```sh
# Build the soak suite binaries (opt-in tag)
make build-soak-test-binaries

# …or run a specific suite directly with ginkgo:
ginkgo --tags soak ./test/integration/soak/port-reuse/ -- \
  --cluster-kubeconfig=$KUBECONFIG \
  --cluster-name=$CLUSTER_NAME \
  --aws-region=$AWS_REGION
```

## Suites

- **port-reuse/** — soaks an ephemeral-source-port-reuse workload
  (aws/aws-network-policy-agent#462). A victim pod behind a restrictive ingress
  policy issues one short-lived request per second while `SO_REUSEADDR` replicas
  churn connections to force port reuse. Runs for 30 minutes and fails on any
  `Verdict DENY` to the victim, which means a conntrack entry for a live flow went
  missing. Liveness gates fail the run fast if the workload or cleanup is inert.
