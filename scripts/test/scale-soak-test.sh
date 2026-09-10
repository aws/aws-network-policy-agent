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

sleep() {
    :
}

npa_kubectl() {
    case "$*" in
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

echo "PASS"
