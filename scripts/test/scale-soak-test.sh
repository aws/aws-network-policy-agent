#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")/.."; pwd)
source "${DIR}/lib/scale-soak.sh"

KUBECONFIG=/tmp/npa-scale-soak-test-kubeconfig
NPA_PROBE_ATTEMPTS=1

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_failure() {
    if "$@"; then
        fail "command unexpectedly succeeded: $*"
    fi
}

npa_require_test_namespace npa-scale npa-scale
npa_require_test_namespace npa-scale-run-1 npa-scale
expect_failure npa_require_test_namespace --all npa-scale
expect_failure npa_require_test_namespace kube-system npa-scale
expect_failure npa_require_test_namespace npa-soak npa-scale

cleanup_args=
npa_kubectl() {
    cleanup_args="$*"
}
npa_cleanup_namespace npa-scale-safe
[[ "$cleanup_args" == "delete namespace/npa-scale-safe --ignore-not-found=true --wait=true --timeout=10m" ]] ||
    fail "cleanup arguments were not safely bounded: ${cleanup_args}"

rendered_churn=$(npa_render_churn_batch scale-7 1 3)
[[ $(grep -c '^kind: Deployment$' <<<"$rendered_churn") == 3 ]] ||
    fail "churn batch did not render three deployments"
[[ $(grep -c '^kind: NetworkPolicy$' <<<"$rendered_churn") == 3 ]] ||
    fail "churn batch did not render three network policies"
grep -q 'name: scale-7-1' <<<"$rendered_churn" ||
    fail "churn batch omitted its first identity"
grep -q 'name: scale-7-3' <<<"$rendered_churn" ||
    fail "churn batch omitted its last identity"

rendered_short_lived_policy=$(npa_render_short_lived_policy)
grep -q 'name: npa-short-lived-policy' <<<"$rendered_short_lived_policy" ||
    fail "short-lived policy omitted its stable name"
grep -q 'npa-test-phase: short-lived' <<<"$rendered_short_lived_policy" ||
    fail "short-lived policy omitted its pod selector"

rendered_short_lived_job=$(npa_render_short_lived_job short-lived-7 50 5)
grep -q 'name: short-lived-7' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its run identity"
grep -q 'parallelism: 50' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its parallelism"
grep -q 'completions: 50' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its completion count"
grep -q 'command: \["/bin/sh", "-c", "sleep 5"\]' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its bounded lifetime"

report_dir=$(mktemp -d)
trap 'rm -rf -- "$report_dir"' EXIT
WORKLOAD_REPORT_PATH="${report_dir}/workload.json"
WORKLOAD_POLICY_SETTLE_SECONDS=10
npa_write_workload_report
grep -q '"policySettleSeconds": 10' "$WORKLOAD_REPORT_PATH" ||
    fail "workload report omitted its policy settle interval"

npa_kubectl() {
    case "$*" in
        "apply -n npa-scale -f -")
            cat >/dev/null
            ;;
        "wait job/short-lived-7 -n npa-scale --for=condition=Complete --timeout=10m")
            ;;
        "delete job/short-lived-7 -n npa-scale --ignore-not-found=true --wait=false --timeout=10m")
            ;;
        *)
            fail "unexpected short-lived round invocation: $*"
            ;;
    esac
}
npa_run_short_lived_round npa-scale short-lived-7 50 5

npa_kubectl() {
    case "$*" in
        "get pods -n npa-scale -l npa-test-run=short-lived-7 --no-headers")
            ;;
        *)
            fail "unexpected short-lived deletion check: $*"
            ;;
    esac
}
npa_require_short_lived_deleted npa-scale short-lived-7

npa_kubectl() {
    case "$*" in
        "get pods -n npa-scale -l npa-test-run=short-lived-7 --no-headers")
            echo short-lived-7-pod
            ;;
        *)
            fail "unexpected short-lived residue check: $*"
            ;;
    esac
}
expect_failure npa_require_short_lived_deleted npa-scale short-lived-7

npa_kubectl() {
    case "$*" in
        "get pods -n npa-scale -l npa-test-run=short-lived-7 --no-headers")
            return 1
            ;;
        *)
            fail "unexpected short-lived verification error check: $*"
            ;;
    esac
}
expect_failure npa_require_short_lived_deleted npa-scale short-lived-7

sleep() {
    :
}

npa_kubectl() {
    case "$*" in
        *npa-unselected-client*)
            echo unselected-ok
            ;;
        *npa-allowed-client*)
            echo npa-ok
            ;;
        *npa-denied-client*)
            return 1
            ;;
        *)
            fail "unexpected kubectl invocation: $*"
            ;;
    esac
}
expect_failure npa_verify_enforcement npa-scale

npa_kubectl() {
    case "$*" in
        *npa-unselected-client*)
            echo unselected-ok
            ;;
        *npa-allowed-client*)
            echo npa-ok
            ;;
        *npa-denied-client*)
            echo NPA_PROBE_DENIED
            ;;
        *)
            fail "unexpected kubectl invocation: $*"
            ;;
    esac
}
npa_verify_enforcement npa-scale

NPA_POLICY_MODE=strict
npa_kubectl() {
    case "$*" in
        *npa-unselected-client*)
            return 1
            ;;
        *npa-allowed-client*)
            echo npa-ok
            ;;
        *npa-denied-client*)
            echo NPA_PROBE_DENIED
            ;;
        *)
            fail "unexpected kubectl invocation: $*"
            ;;
    esac
}
npa_verify_enforcement npa-scale
NPA_POLICY_MODE=standard

npa_kubectl() {
    case "$*" in
        *npa-allowed-client*)
            echo npa-ok
            ;;
        *npa-denied-client*)
            echo NPA_PROBE_ALLOWED
            ;;
        *)
            fail "unexpected kubectl invocation: $*"
            ;;
    esac
}
expect_failure npa_verify_enforcement npa-scale

NPA_POLICY_MODE=standard
WORKLOAD_POLICY_REMOVAL_PROBES=0
WORKLOAD_POLICY_REMOVAL_STATUS=pending
npa_kubectl() {
    case "$*" in
        "delete networkpolicy/npa-probe-policy"*)
            ;;
        *npa-denied-client*)
            echo npa-ok
            ;;
        *)
            fail "unexpected kubectl invocation: $*"
            ;;
    esac
}
npa_probe_policy_removal npa-scale
[[ "$WORKLOAD_POLICY_REMOVAL_STATUS" == pass ]] ||
    fail "standard policy-removal probe did not pass"

NPA_POLICY_MODE=strict
WORKLOAD_POLICY_REMOVAL_PROBES=0
WORKLOAD_POLICY_REMOVAL_STATUS=pending
strict_allow_applied=false
npa_kubectl() {
    case "$*" in
        "delete networkpolicy/npa-probe-policy"*)
            ;;
        "apply -n npa-scale -f -"*)
            strict_allow_applied=true
            ;;
        *npa-denied-client*)
            if [[ "$strict_allow_applied" == true ]]; then
                echo npa-ok
            else
                return 1
            fi
            ;;
        *)
            fail "unexpected kubectl invocation: $*"
            ;;
    esac
}
npa_probe_policy_removal npa-scale
[[ "$WORKLOAD_POLICY_REMOVAL_STATUS" == pass ]] ||
    fail "strict policy-removal probe did not pass"
NPA_POLICY_MODE=standard

echo "PASS"
