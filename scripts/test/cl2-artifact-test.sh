#!/usr/bin/env bash

set -euo pipefail

DIR=$(cd "$(dirname "$0")/.."; pwd)

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
artifact_dir="${test_dir}/artifacts"
fake_clusterloader="${test_dir}/clusterloader2"
profile="${test_dir}/profile.yaml"
kubeconfig="${test_dir}/kubeconfig"
mkdir -p "$artifact_dir"
printf 'name: fake\n' >"$profile"
printf 'apiVersion: v1\nkind: Config\n' >"$kubeconfig"

cat >"$fake_clusterloader" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == --help ]]; then
    printf '%s\n' \
        --dry-run \
        --enable-prometheus-server \
        --prometheus-additional-monitors-path \
        --tear-down-prometheus-server
    exit 0
fi
report_dir=
for arg in "$@"; do
    case "$arg" in
        --report-dir=*) report_dir=${arg#*=} ;;
    esac
done
: "${report_dir:?missing report directory}"
mkdir -p "$report_dir"
printf '<testsuite><failure>working-set assertion marker</failure></testsuite>\n' \
    >"${report_dir}/junit.xml"
printf '{"cluster":"fake"}\n' >"${report_dir}/cl2-metadata.json"
printf 'name: generated-fake\n' >"${report_dir}/generatedConfig_fake.yaml"
printf 'query evidence\n' >"${report_dir}/GenericPrometheusQuery_fake.json"
for ((line = 1; line <= 400; line++)); do
    printf 'workload noise line %s\n' "$line"
done
printf 'GenericPrometheusQuery working-set assertion marker: violation\n'
exit 17
EOF
chmod +x "$fake_clusterloader"

set +e
output=$(
    ARTIFACT_DIR="$artifact_dir" \
        CL2_BIN="$fake_clusterloader" \
        CL2_DRY_RUN=false \
        CL2_EXPECTED_LINUX_NODES=1 \
        CL2_PROFILE_PATH="$profile" \
        CLUSTER_NAME=test-cluster \
        KUBECONFIG="$kubeconfig" \
        "$DIR/run-npa-scale-tests.sh" 2>&1
)
status=$?
set -e

[[ $status == 17 ]] || fail "wrapper returned ${status}, want the ClusterLoader2 status 17"
grep -q 'working-set assertion marker' <<<"$output" ||
    fail "concise failure output omitted the assertion marker"
[[ -s ${artifact_dir}/npa-cl2-test-cluster.log ]] ||
    fail "full ClusterLoader2 log was not published"
[[ -s ${artifact_dir}/npa-cl2-test-cluster-summary.txt ]] ||
    fail "ClusterLoader2 summary was not published"
[[ -s ${artifact_dir}/npa-cl2-test-cluster-junit.xml ]] ||
    fail "ClusterLoader2 JUnit report was not flattened"
[[ -s ${artifact_dir}/npa-cl2-test-cluster-metadata.json ]] ||
    fail "ClusterLoader2 metadata was not flattened"
[[ -s ${artifact_dir}/npa-cl2-test-cluster-generated-config.yaml ]] ||
    fail "generated ClusterLoader2 config was not flattened"
[[ -s ${artifact_dir}/npa-cl2-test-cluster-reports.tar.gz ]] ||
    fail "ClusterLoader2 report archive was not published"
grep -q 'clusterloader2_exit_code=17' \
    "${artifact_dir}/npa-cl2-test-cluster-summary.txt" ||
    fail "summary omitted the ClusterLoader2 exit code"
grep -q 'working-set assertion marker' \
    "${artifact_dir}/npa-cl2-test-cluster-summary.txt" ||
    fail "summary omitted the assertion marker"
tar -tzf "${artifact_dir}/npa-cl2-test-cluster-reports.tar.gz" ./junit.xml \
    >/dev/null ||
    fail "report archive omitted the JUnit report"

echo "PASS"
