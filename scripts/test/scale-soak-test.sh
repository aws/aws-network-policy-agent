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
npa_require_image_reference NPA_TEST_IMAGE \
    public.ecr.aws/docker/library/busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
expect_failure npa_require_image_reference NPA_TEST_IMAGE $'image\nkind: Pod'

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

rendered_scale_churn=$(npa_render_churn_batch scale-7 1 3 true)
grep -q 'npa-scale-workload: "true"' <<<"$rendered_scale_churn" ||
    fail "scale churn omitted its common distribution label"
grep -q 'topologyKey: kubernetes.io/hostname' <<<"$rendered_scale_churn" ||
    fail "scale churn omitted hostname topology spread"
grep -q 'whenUnsatisfiable: DoNotSchedule' <<<"$rendered_scale_churn" ||
    fail "scale churn does not require all expected nodes to participate"
grep -q 'automountServiceAccountToken: false' <<<"$rendered_scale_churn" ||
    fail "scale churn pods mount Kubernetes service-account tokens"
if grep -q 'npa-scale-workload: "true"' <<<"$rendered_churn"; then
    fail "default churn unexpectedly changed the soak placement contract"
fi

rendered_short_lived_policies=$(npa_render_short_lived_policies)
[[ $(grep -c '^kind: NetworkPolicy$' <<<"$rendered_short_lived_policies") == 2 ]] ||
    fail "short-lived workload did not render two network policies"
grep -q 'name: npa-short-lived-default-deny' <<<"$rendered_short_lived_policies" ||
    fail "short-lived policies omitted their default-deny policy"
grep -q 'name: npa-short-lived-policy' <<<"$rendered_short_lived_policies" ||
    fail "short-lived policies omitted their control policy"
[[ $(grep -c '^      npa-test-phase: short-lived$' <<<"$rendered_short_lived_policies") == 2 ]] ||
    fail "both short-lived policies must select the churn pods"
grep -q 'app: npa-probe-server' <<<"$rendered_short_lived_policies" ||
    fail "short-lived policies omitted their control destination"
grep -q 'port: 8081' <<<"$rendered_short_lived_policies" ||
    fail "short-lived policies omitted their allowed control port"
if grep -q 'port: 8080' <<<"$rendered_short_lived_policies"; then
    fail "short-lived policies unexpectedly allowed their denied target port"
fi

rendered_short_lived_job=$(npa_render_short_lived_job short-lived-7 100 5)
grep -q 'name: short-lived-7' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its run identity"
grep -q 'parallelism: 100' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its parallelism"
grep -q 'completions: 100' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its completion count"
grep -q '^        npa-test-phase: short-lived$' <<<"$rendered_short_lived_job" ||
    fail "short-lived job pod label does not match both policy selectors"
grep -q 'NPA_PROBE_SERVER_SERVICE_HOST' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its policy probe target"
grep -q 'http://\$host:8081/' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its allowed control request"
grep -q 'http://\$host:8080/' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its denied request"
grep -q 'never proved allowed control plus denied target' <<<"$rendered_short_lived_job" ||
    fail "short-lived job omitted its policy-enforcement verdict"

rendered_scale_short_lived_job=$(npa_render_short_lived_job short-lived-7 100 5 true)
grep -q 'npa-scale-workload: "true"' <<<"$rendered_scale_short_lived_job" ||
    fail "scale short-lived job omitted its common distribution label"
grep -q 'topologyKey: kubernetes.io/hostname' <<<"$rendered_scale_short_lived_job" ||
    fail "scale short-lived job omitted hostname topology spread"
grep -q 'automountServiceAccountToken: false' <<<"$rendered_scale_short_lived_job" ||
    fail "scale short-lived pods mount Kubernetes service-account tokens"

report_dir=$(mktemp -d)
trap 'rm -rf -- "$report_dir"' EXIT
WORKLOAD_REPORT_PATH="${report_dir}/workload.json"
WORKLOAD_BATCH_SIZE=50
WORKLOAD_POLICY_SETTLE_SECONDS=10
WORKLOAD_POLICY_PODS_PER_ROUND=50
WORKLOAD_SHORT_LIVED_POLICY_ATTESTATIONS=2000
WORKLOAD_SHORT_LIVED_LIFETIME_SECONDS=5
npa_write_workload_report
grep -q '"batchSize": 50' "$WORKLOAD_REPORT_PATH" ||
    fail "workload report omitted its batch size"
grep -q '"policySettleSeconds": 10' "$WORKLOAD_REPORT_PATH" ||
    fail "workload report omitted its policy settle interval"
grep -q '"policyPodsPerRound": 50' "$WORKLOAD_REPORT_PATH" ||
    fail "workload report omitted its policy pod count"
grep -q '"shortLivedPolicyAttestations": 2000' "$WORKLOAD_REPORT_PATH" ||
    fail "workload report omitted its short-lived policy attestations"
grep -q '"shortLivedLifetimeSeconds": 5' "$WORKLOAD_REPORT_PATH" ||
    fail "workload report omitted its short-lived pod lifetime"

WORKLOAD_PROFILE_ID=npa-policy-churn-v4
WORKLOAD_STATUS=pass
WORKLOAD_POLICY_ROUNDS_REQUESTED=20
WORKLOAD_POLICY_ROUNDS_COMPLETED=20
WORKLOAD_SHORT_LIVED_PODS_PER_ROUND=100
WORKLOAD_SHORT_LIVED_ROUNDS_REQUESTED=20
WORKLOAD_SHORT_LIVED_ROUNDS_COMPLETED=20
WORKLOAD_SHORT_LIVED_PODS=2000
WORKLOAD_SHORT_LIVED_POLICY_ATTESTATIONS=2000
WORKLOAD_ROUNDS_COMPLETED=40
WORKLOAD_CHURN_PODS=3000
npa_validate_scale_completion
WORKLOAD_SHORT_LIVED_POLICY_ATTESTATIONS=1999
expect_failure npa_validate_scale_completion
WORKLOAD_SHORT_LIVED_POLICY_ATTESTATIONS=2000
WORKLOAD_POLICY_ROUNDS_COMPLETED=19
expect_failure npa_validate_scale_completion
WORKLOAD_POLICY_ROUNDS_COMPLETED=20

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
npa_run_short_lived_round npa-scale short-lived-7 100 5

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
        "get nodes -l kubernetes.io/os=linux -o jsonpath="*)
            printf 'node-a\nnode-b\n'
            ;;
        "get pods -n npa-scale -l npa-scale-workload=true -o jsonpath="*)
            printf 'node-a\nnode-b\n'
            ;;
        *)
            fail "unexpected node coverage invocation: $*"
            ;;
    esac
}
npa_require_workload_node_coverage npa-scale 2

npa_kubectl() {
    case "$*" in
        "get nodes -l kubernetes.io/os=linux -o jsonpath="*)
            printf 'node-a\nnode-b\n'
            ;;
        "get pods -n npa-scale -l npa-scale-workload=true -o jsonpath="*)
            printf 'node-a\n'
            ;;
        *)
            fail "unexpected incomplete node coverage invocation: $*"
            ;;
    esac
}
expect_failure npa_require_workload_node_coverage npa-scale 2

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

missing_state_dir=$(mktemp -d)
fake_bin=$(mktemp -d)
cleanup_kubectl_log="${missing_state_dir}/kubectl.log"
cat >"${fake_bin}/kubectl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${NPA_CLEANUP_KUBECTL_LOG:?}"
EOF
chmod +x "${fake_bin}/kubectl"
if NPA_REQUIRE_WORKLOAD_STATE=true \
    SCENARIO_STATE_DIR=$missing_state_dir \
    KUBECONFIG=$KUBECONFIG \
    NPA_CLEANUP_KUBECTL_LOG=$cleanup_kubectl_log \
    PATH="${fake_bin}:${PATH}" \
    bash "${DIR}/run-npa-cleanup.sh"; then
    fail "scale cleanup accepted a missing workload state file"
fi
grep -q 'delete namespace/npa-scale-evidence --ignore-not-found=true --wait=true --timeout=10m' \
    "$cleanup_kubectl_log" ||
    fail "scale cleanup did not remove BPF readers after a missing workload state"

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
