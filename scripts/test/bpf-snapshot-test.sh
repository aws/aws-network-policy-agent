#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")/.."; pwd)
NPA_BPF_LIBRARY_ONLY=true
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
EOF
cat >"$full_load" <<'EOF'
node-a	map	global_aws_conntrack_map
node-a	map	global_policy_events
node-a	map	scale-map
node-a	program	scale-ingress
EOF
cp "$baseline" "$recovery"

npa_bpf_assert_activity "$baseline" "$full_load" "$added"
grep -q $'\tprogram\tscale-ingress$' "$added" ||
    fail "activity assertion omitted the added program identity"
grep -q $'\tmap\tscale-map$' "$added" ||
    fail "activity assertion omitted the added map identity"
npa_bpf_assert_drain "$baseline" "$recovery" "$residual"
[[ ! -s $residual ]] || fail "clean recovery produced residual identities"

cat >>"$recovery" <<'EOF'
node-a	map	leaked-map
EOF
expect_failure npa_bpf_assert_drain "$baseline" "$recovery" "$residual"
grep -q $'\tmap\tleaked-map$' "$residual" ||
    fail "drain assertion omitted the leaked identity"

cat >"$full_load" <<'EOF'
node-a	map	global_aws_conntrack_map
node-a	map	global_policy_events
node-a	map	scale-map
EOF
expect_failure npa_bpf_assert_activity "$baseline" "$full_load" "$added"

KUBECONFIG=/tmp/npa-bpf-snapshot-test-kubeconfig
CL2_EXPECTED_LINUX_NODES=2
ARTIFACT_DIR=$test_dir
NPA_BPF_NAMESPACE=npa-scale-evidence-test
npa_bpf_kubectl() {
    case "$1" in
        get)
            printf 'node-a\treader-a\nnode-b\treader-b\n'
            ;;
        exec)
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

echo "PASS"
