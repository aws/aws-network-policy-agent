#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")/.."; pwd)
source "${DIR}/run-npa-bpf-snapshot.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_failure() {
    if "$@"; then
        fail "command unexpectedly succeeded: $*"
    fi
}

test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT

baseline="${test_dir}/baseline.tsv"
full_load="${test_dir}/full-load.tsv"
recovery="${test_dir}/recovery.tsv"
added="${test_dir}/added.tsv"
residual="${test_dir}/residual.tsv"

cat >"$baseline" <<'EOF'
node-a	map	global_aws_conntrack_map
node-a	map	global_policy_events
node-a	reader	present
node-b	map	global_aws_conntrack_map
node-b	map	global_policy_events
node-b	reader	present
EOF
cat >"$full_load" <<'EOF'
node-a	map	global_aws_conntrack_map
node-a	map	global_policy_events
node-a	map	scale-map
node-a	program	scale-ingress
node-a	reader	present
node-b	map	global_aws_conntrack_map
node-b	map	global_policy_events
node-b	map	scale-map
node-b	program	scale-ingress
node-b	reader	present
EOF
cp "$baseline" "$recovery"

CL2_EXPECTED_LINUX_NODES=2
npa_bpf_assert_activity "$baseline" "$full_load" "$added"
grep -q $'\tprogram\tscale-ingress$' "$added" ||
    fail "activity assertion omitted the added program identity"
grep -q $'\tmap\tscale-map$' "$added" ||
    fail "activity assertion omitted the added map identity"
npa_bpf_assert_drain "$baseline" "$recovery" "$residual"
[[ ! -s $residual ]] || fail "clean recovery produced residual identities"

grep -v '^node-b' "$baseline" >"$recovery"
expect_failure npa_bpf_assert_drain "$baseline" "$recovery" "$residual"

cp "$baseline" "$recovery"
cat >>"$recovery" <<'EOF'
node-a	map	leaked-map
EOF
sort -o "$recovery" "$recovery"
expect_failure npa_bpf_assert_drain "$baseline" "$recovery" "$residual"
grep -q $'\tmap\tleaked-map$' "$residual" ||
    fail "drain assertion omitted the leaked identity"

cat >"$full_load" <<'EOF'
node-a	map	global_aws_conntrack_map
node-a	map	global_policy_events
node-a	map	scale-map
node-a	reader	present
node-b	map	global_aws_conntrack_map
node-b	map	global_policy_events
node-b	map	scale-map
node-b	program	scale-ingress
node-b	reader	present
EOF
expect_failure npa_bpf_assert_activity "$baseline" "$full_load" "$added"

NPA_BPF_NAMESPACE=other
expect_failure npa_bpf_validate_inputs
NPA_BPF_NAMESPACE=$NPA_BPF_OWNED_NAMESPACE
NPA_BPF_READER_IMAGE=untrusted
expect_failure npa_bpf_validate_inputs
NPA_BPF_READER_IMAGE=$NPA_BPF_PINNED_READER_IMAGE
npa_bpf_validate_inputs

KUBECONFIG=/tmp/npa-bpf-snapshot-test-kubeconfig
CL2_EXPECTED_LINUX_NODES=2
ARTIFACT_DIR=$test_dir
NPA_BPF_NAMESPACE=npa-scale-evidence-test
npa_bpf_kubectl() {
    case "$*" in
        "get nodes -l kubernetes.io/os=linux -o jsonpath="*)
            printf 'node-a\nnode-b\n'
            ;;
        "get pods -n npa-scale-evidence-test -l app=npa-bpffs-reader -o jsonpath="*)
            printf 'node-a\treader-a\nnode-b\treader-b\n'
            ;;
        exec*)
            if [[ $4 == reader-b ]]; then
                return 1
            fi
            printf 'map=baseline-map\nprogram=baseline-program\n'
            ;;
        *)
            fail "unexpected bpffs capture invocation: $*"
            ;;
    esac
}
expect_failure npa_bpf_capture "${test_dir}/capture.tsv"
[[ ! -e ${test_dir}/capture.tsv ]] ||
    fail "failed node capture published partial bpffs evidence"

if NPA_BPF_LIBRARY_ONLY=true bash "${DIR}/run-npa-bpf-snapshot.sh" >/dev/null 2>&1; then
    fail "NPA_BPF_LIBRARY_ONLY bypassed direct BPF execution"
fi

echo "PASS"
