#!/usr/bin/env bash

# Captures exact NPA pinned eBPF identities on every Linux node. ClusterLoader2
# invokes this at baseline, full load, and recovery; a non-zero result becomes
# part of the CL2/Hydra verdict.

set -euo pipefail

NPA_BPF_NAMESPACE=${NPA_BPF_NAMESPACE:-npa-scale-evidence}
NPA_BPF_READER_IMAGE=${NPA_BPF_READER_IMAGE:-public.ecr.aws/docker/library/busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}
NPA_BPF_BASELINE_SETTLE_SECONDS=${NPA_BPF_BASELINE_SETTLE_SECONDS:-30}

npa_bpf_new_identities() {
    local baseline=$1
    local current=$2
    comm -13 "$baseline" "$current"
}

npa_bpf_assert_activity() {
    local baseline=$1
    local full_load=$2
    local added=$3

    npa_bpf_new_identities "$baseline" "$full_load" >"$added"
    if ! grep -q $'\tprogram\t' "$added"; then
        echo "full load added no pinned NPA program identity" >&2
        return 1
    fi
    if ! grep -q $'\tmap\t' "$added"; then
        echo "full load added no pinned NPA map identity" >&2
        return 1
    fi
}

npa_bpf_assert_drain() {
    local baseline=$1
    local recovery=$2
    local residual=$3

    npa_bpf_new_identities "$baseline" "$recovery" >"$residual"
    if [[ -s $residual ]]; then
        echo "recovery retained pinned NPA identities that were absent at baseline:" >&2
        head -n 100 "$residual" >&2
        return 1
    fi
}

npa_bpf_kubectl() {
    kubectl --kubeconfig "$KUBECONFIG" "$@"
}

npa_bpf_ensure_readers() {
    npa_bpf_kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${NPA_BPF_NAMESPACE}
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: npa-bpffs-reader
  namespace: ${NPA_BPF_NAMESPACE}
spec:
  selector:
    matchLabels:
      app: npa-bpffs-reader
  template:
    metadata:
      labels:
        app: npa-bpffs-reader
    spec:
      nodeSelector:
        kubernetes.io/os: linux
      tolerations:
        - operator: Exists
      containers:
        - name: reader
          image: ${NPA_BPF_READER_IMAGE}
          command: ["/bin/sh", "-c", "exec sleep 86400"]
          resources:
            requests:
              cpu: 1m
              memory: 4Mi
            limits:
              memory: 32Mi
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
            readOnlyRootFilesystem: true
            runAsUser: 0
          volumeMounts:
            - name: host-bpffs
              mountPath: /host-bpf
              readOnly: true
      volumes:
        - name: host-bpffs
          hostPath:
            path: /sys/fs/bpf
            type: Directory
EOF

    npa_bpf_kubectl rollout status \
        daemonset/npa-bpffs-reader \
        -n "$NPA_BPF_NAMESPACE" \
        --timeout=10m

    local ready
    ready=$(npa_bpf_kubectl get daemonset/npa-bpffs-reader \
        -n "$NPA_BPF_NAMESPACE" \
        -o jsonpath='{.status.numberReady}')
    if [[ $ready != "$CL2_EXPECTED_LINUX_NODES" ]]; then
        printf 'NPA bpffs readers ready=%s, want %s\n' \
            "${ready:-0}" "$CL2_EXPECTED_LINUX_NODES" >&2
        return 1
    fi
}

npa_bpf_capture() {
    local destination=$1
    local temporary="${destination}.tmp.$$"
    : >"$temporary"

    local pod_rows
    pod_rows=$(npa_bpf_kubectl get pods \
        -n "$NPA_BPF_NAMESPACE" \
        -l app=npa-bpffs-reader \
        -o jsonpath='{range .items[*]}{.spec.nodeName}{"\t"}{.metadata.name}{"\n"}{end}')

    local observed=0
    while IFS=$'\t' read -r node pod; do
        [[ -n $node && -n $pod ]] || continue
        local evidence
        if ! evidence=$(
            npa_bpf_kubectl exec \
                -n "$NPA_BPF_NAMESPACE" \
                "$pod" \
                -c reader \
                -- /bin/sh -c '
                    set -eu
                    root=/host-bpf/globals/aws
                    maps="$root/maps"
                    programs="$root/programs"
                    if [ ! -d "$maps" ]; then
                        echo "NPA bpffs map directory is missing" >&2
                        exit 1
                    fi
                    if [ -d "$programs" ]; then
                        for path in "$programs"/*; do
                            [ "$path" = "$programs/*" ] && break
                            printf "program=%s\n" "${path##*/}"
                        done
                    fi
                    for path in "$maps"/*; do
                        [ "$path" = "$maps/*" ] && break
                        printf "map=%s\n" "${path##*/}"
                    done
                '
        ); then
            printf 'failed to capture NPA bpffs evidence from node %s using pod %s\n' \
                "$node" "$pod" >&2
            rm -f -- "$temporary"
            return 1
        fi
        observed=$((observed + 1))
        while IFS='=' read -r kind identity; do
            [[ -n $kind && -n $identity ]] || continue
            printf '%s\t%s\t%s\n' "$node" "$kind" "$identity" >>"$temporary"
        done <<<"$evidence"
    done <<<"$pod_rows"

    if [[ $observed != "$CL2_EXPECTED_LINUX_NODES" ]]; then
        printf 'captured NPA bpffs evidence from %s nodes, want %s\n' \
            "$observed" "$CL2_EXPECTED_LINUX_NODES" >&2
        rm -f -- "$temporary"
        return 1
    fi

    sort -u "$temporary" >"$destination"
    rm -f -- "$temporary"
    npa_bpf_publish "$destination"
}

npa_bpf_publish() {
    local source=$1
    local cluster=${CLUSTER_NAME:-manual}
    cluster=${cluster//[^a-zA-Z0-9_.-]/-}
    cp "$source" "${ARTIFACT_DIR}/${cluster}-$(basename -- "$source")"
}

npa_bpf_main() {
    local phase=${1:-}
    case "$phase" in
        baseline | full-load | recovery) ;;
        *)
            echo "usage: $0 baseline|full-load|recovery" >&2
            return 2
            ;;
    esac

    : "${KUBECONFIG:?KUBECONFIG must identify the test cluster}"
    : "${SCENARIO_STATE_DIR:?SCENARIO_STATE_DIR must be set}"
    : "${CL2_EXPECTED_LINUX_NODES:?CL2_EXPECTED_LINUX_NODES must be set}"
    if [[ ! $NPA_BPF_BASELINE_SETTLE_SECONDS =~ ^[0-9]+$ ]]; then
        echo "NPA_BPF_BASELINE_SETTLE_SECONDS must be a non-negative integer" >&2
        return 2
    fi
    for command in comm cp grep head kubectl sort; do
        command -v "$command" >/dev/null 2>&1 || {
            printf '%s is required\n' "$command" >&2
            return 127
        }
    done
    ARTIFACT_DIR=${ARTIFACT_DIR:-log}
    mkdir -p "$SCENARIO_STATE_DIR" "$ARTIFACT_DIR"

    local baseline="${SCENARIO_STATE_DIR}/npa-bpf-baseline.tsv"
    local snapshot="${SCENARIO_STATE_DIR}/npa-bpf-${phase}.tsv"

    case "$phase" in
        baseline)
            npa_bpf_ensure_readers
            sleep "$NPA_BPF_BASELINE_SETTLE_SECONDS"
            npa_bpf_capture "$snapshot"
            ;;
        full-load)
            [[ -s $baseline ]] || {
                echo "NPA baseline eBPF snapshot is missing" >&2
                return 1
            }
            npa_bpf_capture "$snapshot"
            local added="${SCENARIO_STATE_DIR}/npa-bpf-full-load-added.tsv"
            npa_bpf_assert_activity "$baseline" "$snapshot" "$added"
            npa_bpf_publish "$added"
            ;;
        recovery)
            [[ -s $baseline ]] || {
                echo "NPA baseline eBPF snapshot is missing" >&2
                return 1
            }
            npa_bpf_capture "$snapshot"
            local residual="${SCENARIO_STATE_DIR}/npa-bpf-recovery-residual.tsv"
            npa_bpf_assert_drain "$baseline" "$snapshot" "$residual"
            npa_bpf_publish "$residual"
            npa_bpf_kubectl delete namespace "$NPA_BPF_NAMESPACE" \
                --ignore-not-found=true \
                --wait=false
            ;;
    esac
}

if [[ ${NPA_BPF_LIBRARY_ONLY:-false} != true ]]; then
    npa_bpf_main "$@"
fi
