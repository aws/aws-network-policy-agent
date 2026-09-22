#!/usr/bin/env bash

# Runs the locked NPA scale workload through a component-owned ClusterLoader2
# profile. The workload and exact eBPF identity checks remain runnable against
# any existing cluster; Hydra supplies the profile and monitor set.

set -euo pipefail

CL2_BIN=${CL2_BIN:-clusterloader2}
CL2_EXPECTED_SHA256=${CL2_EXPECTED_SHA256:-}
CL2_UPSTREAM_REVISION=${CL2_UPSTREAM_REVISION:-unknown}
CL2_DRY_RUN=${CL2_DRY_RUN:-false}
CL2_EXPECTED_LINUX_NODES=${CL2_EXPECTED_LINUX_NODES:-${EXPECTED_LINUX_NODES:-7}}
NPA_POLICY_MODE=${NPA_POLICY_MODE:-standard}
NPA_SCALE_NAMESPACE=${NPA_SCALE_NAMESPACE:-npa-scale}
NPA_SCALE_STABLE_TARGETS=${NPA_SCALE_STABLE_TARGETS:-100}
NPA_SCALE_TARGETS=${NPA_SCALE_TARGETS:-50}
NPA_SCALE_BATCH_SIZE=${NPA_SCALE_BATCH_SIZE:-50}
NPA_SCALE_CYCLES=${NPA_SCALE_CYCLES:-20}
NPA_SCALE_CYCLE_SECONDS=${NPA_SCALE_CYCLE_SECONDS:-60}
NPA_SCALE_POLICY_SETTLE_SECONDS=${NPA_SCALE_POLICY_SETTLE_SECONDS:-10}
NPA_SCALE_SHORT_LIVED_TARGETS=${NPA_SCALE_SHORT_LIVED_TARGETS:-100}
NPA_SCALE_SHORT_LIVED_ROUNDS=${NPA_SCALE_SHORT_LIVED_ROUNDS:-20}
NPA_SCALE_SHORT_LIVED_INTERVAL_SECONDS=${NPA_SCALE_SHORT_LIVED_INTERVAL_SECONDS:-60}
NPA_SCALE_SHORT_LIVED_LIFETIME_SECONDS=${NPA_SCALE_SHORT_LIVED_LIFETIME_SECONDS:-5}
NPA_SCALE_BASELINE_SETTLE=${NPA_SCALE_BASELINE_SETTLE:-60s}
NPA_SCALE_SCRAPE_SETTLE=${NPA_SCALE_SCRAPE_SETTLE:-60s}
NPA_SCALE_RECOVERY_DELAY=${NPA_SCALE_RECOVERY_DELAY:-5m}
NPA_SCALE_WORKLOAD_TIMEOUT=${NPA_SCALE_WORKLOAD_TIMEOUT:-60m}
NPA_SCALE_CLEANUP_TIMEOUT=${NPA_SCALE_CLEANUP_TIMEOUT:-20m}
NPA_SCALE_BPF_TIMEOUT=${NPA_SCALE_BPF_TIMEOUT:-10m}
WORKLOAD_PROFILE_ID=${WORKLOAD_PROFILE_ID:-npa-policy-churn-v4}

validate_positive_integer() {
    local name=$1
    local value=$2
    if [[ ! $value =~ ^[1-9][0-9]*$ ]]; then
        printf '%s must be a positive integer; got %q\n' "$name" "$value" >&2
        exit 2
    fi
}

for name in \
    CL2_EXPECTED_LINUX_NODES \
    NPA_SCALE_STABLE_TARGETS \
    NPA_SCALE_TARGETS \
    NPA_SCALE_BATCH_SIZE \
    NPA_SCALE_CYCLES \
    NPA_SCALE_CYCLE_SECONDS \
    NPA_SCALE_POLICY_SETTLE_SECONDS \
    NPA_SCALE_SHORT_LIVED_TARGETS \
    NPA_SCALE_SHORT_LIVED_ROUNDS \
    NPA_SCALE_SHORT_LIVED_INTERVAL_SECONDS \
    NPA_SCALE_SHORT_LIVED_LIFETIME_SECONDS; do
    validate_positive_integer "$name" "${!name}"
done
if [[ $NPA_POLICY_MODE != standard && $NPA_POLICY_MODE != strict ]]; then
    printf 'NPA_POLICY_MODE must be standard or strict; got %q\n' "$NPA_POLICY_MODE" >&2
    exit 2
fi
if [[ $WORKLOAD_PROFILE_ID != npa-policy-churn-v4 ]]; then
    printf 'Unsupported NPA scale workload profile %q\n' "$WORKLOAD_PROFILE_ID" >&2
    exit 2
fi
if [[ $CL2_DRY_RUN != true && $CL2_DRY_RUN != false ]]; then
    printf 'CL2_DRY_RUN must be true or false; got %q\n' "$CL2_DRY_RUN" >&2
    exit 2
fi
for command in "$CL2_BIN" awk comm grep realpath sha256sum sort tee; do
    command -v "$command" >/dev/null 2>&1 || {
        printf '%s is required\n' "$command" >&2
        exit 127
    }
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CL2_PROFILE_PATH=${CL2_PROFILE_PATH:-"${script_dir}/scale/cl2-config.yaml"}
if [[ ! -f $CL2_PROFILE_PATH ]]; then
    printf 'ClusterLoader2 profile does not exist: %s\n' "$CL2_PROFILE_PATH" >&2
    exit 2
fi
CL2_PROFILE_PATH=$(realpath "$CL2_PROFILE_PATH")

if [[ -n ${CL2_MONITORS_PATH:-} ]]; then
    if [[ ! -d $CL2_MONITORS_PATH ]]; then
        printf 'ClusterLoader2 monitor directory does not exist: %s\n' \
            "$CL2_MONITORS_PATH" >&2
        exit 2
    fi
    CL2_MONITORS_PATH=$(realpath "$CL2_MONITORS_PATH")
fi

clusterloader_path=$(command -v "$CL2_BIN")
clusterloader_sha256=$(sha256sum "$clusterloader_path")
clusterloader_sha256=${clusterloader_sha256%% *}
if [[ -n $CL2_EXPECTED_SHA256 && $clusterloader_sha256 != "$CL2_EXPECTED_SHA256" ]]; then
    printf 'ClusterLoader2 SHA-256 mismatch: got %s, want %s\n' \
        "$clusterloader_sha256" "$CL2_EXPECTED_SHA256" >&2
    exit 2
fi
cl2_help=$("$CL2_BIN" --help 2>&1 || true)
for required_flag in \
    --dry-run \
    --enable-prometheus-server \
    --prometheus-additional-monitors-path \
    --tear-down-prometheus-server; do
    if ! grep -q -- "$required_flag" <<<"$cl2_help"; then
        printf '%s does not expose required flag %s\n' "$CL2_BIN" "$required_flag" >&2
        exit 2
    fi
done

if [[ -n ${KUBE_CONFIG_PATH:-} && -z ${KUBECONFIG:-} ]]; then
    export KUBECONFIG=$KUBE_CONFIG_PATH
fi
if [[ $CL2_DRY_RUN == false ]]; then
    KUBECONFIG=${KUBECONFIG:-"${HOME:?HOME must be set}/.kube/config"}
else
    KUBECONFIG=${KUBECONFIG:-"${script_dir}/scale/kubeconfig.dry-run.yaml"}
fi
export KUBECONFIG

export NPA_POLICY_MODE NPA_SCALE_NAMESPACE NPA_SCALE_STABLE_TARGETS
export NPA_SCALE_TARGETS NPA_SCALE_BATCH_SIZE NPA_SCALE_CYCLES
export NPA_SCALE_CYCLE_SECONDS NPA_SCALE_POLICY_SETTLE_SECONDS
export NPA_SCALE_SHORT_LIVED_TARGETS NPA_SCALE_SHORT_LIVED_ROUNDS
export NPA_SCALE_SHORT_LIVED_INTERVAL_SECONDS NPA_SCALE_SHORT_LIVED_LIFETIME_SECONDS
export NPA_DEFER_CLEANUP=true

export CL2_NPA_WORKLOAD_SCRIPT
CL2_NPA_WORKLOAD_SCRIPT=$(realpath "${script_dir}/run-npa-scale-workload.sh")
export CL2_NPA_CLEANUP_SCRIPT
CL2_NPA_CLEANUP_SCRIPT=$(realpath "${script_dir}/run-npa-cleanup.sh")
export CL2_NPA_BPF_SNAPSHOT_SCRIPT
CL2_NPA_BPF_SNAPSHOT_SCRIPT=$(realpath "${script_dir}/run-npa-bpf-snapshot.sh")
export CL2_NPA_POLICY_MODE=$NPA_POLICY_MODE
export CL2_NPA_BASELINE_SETTLE=$NPA_SCALE_BASELINE_SETTLE
export CL2_NPA_SCRAPE_SETTLE=$NPA_SCALE_SCRAPE_SETTLE
export CL2_NPA_RECOVERY_DELAY=$NPA_SCALE_RECOVERY_DELAY
export CL2_NPA_WORKLOAD_TIMEOUT=$NPA_SCALE_WORKLOAD_TIMEOUT
export CL2_NPA_CLEANUP_TIMEOUT=$NPA_SCALE_CLEANUP_TIMEOUT
export CL2_NPA_BPF_TIMEOUT=$NPA_SCALE_BPF_TIMEOUT

# The scale run is ephemeral; no persistent volume is required for Prometheus.
export CL2_PROMETHEUS_PVC_ENABLED=false
export PROMETHEUS_STORAGE_CLASS_PROVISIONER=ebs.csi.aws.com
export PROMETHEUS_STORAGE_CLASS_VOLUME_TYPE=gp3
export CL2_PROMETHEUS_KUBELET_MEMORY_SCALE_FACTOR=${CL2_PROMETHEUS_KUBELET_MEMORY_SCALE_FACTOR:-4}

safe_cluster_name=${CLUSTER_NAME:-local}
safe_cluster_name=${safe_cluster_name//[^a-zA-Z0-9_.-]/-}
artifact_root=${ARTIFACT_DIR:-log}
report_dir=${NPA_SCALE_REPORT_DIR:-"${artifact_root}/clusterloader2-${safe_cluster_name}"}
mkdir -p "$report_dir"

cat >"${report_dir}/metadata.txt" <<EOF
scenario_id=${TEST_SCENARIO_ID:-manual}
workload_profile_id=${WORKLOAD_PROFILE_ID}
workload_revision=${WORKLOAD_GIT_REVISION:-unknown}
policy_mode=${NPA_POLICY_MODE}
clusterloader2_path=${clusterloader_path}
clusterloader2_sha256=${clusterloader_sha256}
clusterloader2_upstream_revision=${CL2_UPSTREAM_REVISION}
profile_path=${CL2_PROFILE_PATH}
monitors_path=${CL2_MONITORS_PATH:-none}
linux_nodes=${CL2_EXPECTED_LINUX_NODES}
stable_targets=${NPA_SCALE_STABLE_TARGETS}
policy_cycles=${NPA_SCALE_CYCLES}
policy_targets_per_cycle=${NPA_SCALE_TARGETS}
short_lived_rounds=${NPA_SCALE_SHORT_LIVED_ROUNDS}
short_lived_targets_per_round=${NPA_SCALE_SHORT_LIVED_TARGETS}
EOF

cl2_args=(
    -v=2
    "--testconfig=${CL2_PROFILE_PATH}"
    --provider=eks
    "--nodes=${CL2_EXPECTED_LINUX_NODES}"
    --enable-exec-service=false
    "--report-dir=${report_dir}"
    "--kubeconfig=${KUBECONFIG}"
)
if [[ -n ${CL2_MONITORS_PATH:-} ]]; then
    cl2_args+=(
        --enable-prometheus-server=true
        --tear-down-prometheus-server=true
        --prometheus-scrape-kube-proxy=false
        --prometheus-scrape-kubelets=true
        "--prometheus-additional-monitors-path=${CL2_MONITORS_PATH}"
    )
fi
if [[ $CL2_DRY_RUN == true ]]; then
    cl2_args+=(
        --dry-run=true
        --skip-cluster-verification=true
    )
fi

printf 'Running NPA %s scale profile %s with ClusterLoader2 %s\n' \
    "$NPA_POLICY_MODE" "$CL2_PROFILE_PATH" "$clusterloader_sha256"
if [[ $CL2_DRY_RUN == true ]]; then
    set +e
    "$CL2_BIN" "${cl2_args[@]}" 2>&1 | tee "${report_dir}/clusterloader2.log"
    clusterloader_status=${PIPESTATUS[0]}
    set -e
    generated_configs=("${report_dir}"/generatedConfig_*.yaml)
    if [[ ! -s ${generated_configs[0]} ]]; then
        printf 'ClusterLoader2 dry run produced no generated config (status %s)\n' \
            "$clusterloader_status" >&2
        exit 1
    fi
    printf 'ClusterLoader2 compiled the NPA scale profile: %s\n' \
        "${generated_configs[0]}"
    exit 0
fi

"$CL2_BIN" "${cl2_args[@]}" 2>&1 | tee "${report_dir}/clusterloader2.log"

printf 'NPA scale profile passed; reports: %s\n' "$report_dir"
