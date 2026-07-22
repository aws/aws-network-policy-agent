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
ginkgo --tags soak ./test/integration/soak/conntrack-race/ -- \
  --cluster-kubeconfig=$KUBECONFIG \
  --cluster-name=$CLUSTER_NAME \
  --aws-region=$AWS_REGION
```

## Suites

- **conntrack-race/** — reproduces the conntrack GC snapshot-vs-iterate race
  (aws/aws-network-policy-agent#462) and validates the `last_seen` fix. Fails on
  stock NPA (return-flow `Verdict DENY` when cleanup deletes a live reused entry);
  passes on the patched agent (`Conntrack cleanup Skip (in use)` fires, 0 DENY).
  Two-sided assertions (liveness + fix-engaged + no-wedge), early-exit on
  confirmation, 30-minute cap.
