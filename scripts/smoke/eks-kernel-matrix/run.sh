#!/usr/bin/env bash
set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"
# The EKS docs designate the amazon-eks-ami GitHub release notes as the only
# source for per-AMI kernel versions (no AWS API exposes them; see
# docs.aws.amazon.com/eks/latest/userguide/eks-linux-ami-versions.html).
# Fetch the release body through the Releases API so we parse the
# author-written markup rather than GitHub's rendered HTML. GITHUB_TOKEN is
# optional but avoids unauthenticated rate limits on shared CI runner IPs.
RELEASE_URL="https://api.github.com/repos/awslabs/amazon-eks-ami/releases/tags"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for cmd in aws curl jq awk; do
    command -v "$cmd" >/dev/null || { echo "missing dependency: $cmd" >&2; exit 1; }
done

fetch_release_body() {
    local tag="$1" response message
    # args is never empty so the expansion is safe under set -u on bash < 4.4.
    local -a args=(-sSL -H "Accept: application/vnd.github+json")
    [[ -z "${GITHUB_TOKEN:-}" ]] || args+=(-H "Authorization: Bearer $GITHUB_TOKEN")
    # No curl -f: on 403/404 GitHub returns a JSON error we want to surface.
    response=$(curl "${args[@]}" "$RELEASE_URL/$tag") || {
        echo "failed to fetch release $tag" >&2; return 1
    }
    jq -er '.body | select(type == "string" and length > 0)' <<<"$response" || {
        message=$(jq -r '.message // empty' <<<"$response" 2>/dev/null || true)
        echo "unexpected API response for $tag: ${message:-${response:0:200}}" >&2
        return 1
    }
}

kernel_from_release() {
    local file="$1" version="$2"
    awk -v target="$version" '
        function value(line) {
            gsub(/<[^>]*>/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            return line
        }
        index($0, "<summary><b>Kubernetes " target "</b></summary>") { section=1; next }
        section && /<summary><b>Kubernetes / { exit }
        section && /<th>Package<\/th>/ { header=1; column=0; next }
        header && /<\/tr>/ { header=0; next }
        header && /<th>/ {
            column++
            if (value($0) == "AL2023_x86_64_STANDARD") standard=column
            next
        }
        section && standard && /<td>kernel[^<]*<\/td>/ { row=1; column=0; next }
        row && /<\/tr>/ { row=0; next }
        row && /<td/ {
            span=1
            if (match($0, /colspan="[0-9]+"/)) {
                text=substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", text); span=text+0
            }
            cell=value($0)
            if (column < standard && column+span >= standard && cell ~ /^[0-9]+\.[0-9]+\./) {
                print cell; exit
            }
            column+=span
        }
    ' "$file"
}

# --include-all returns every version regardless of the API's default
# filtering; the status filter below keeps only supported ones.
versions_json=$(aws eks describe-cluster-versions --region "$REGION" --include-all --output json)
mapfile -t versions < <(jq -r '
    [.clusterVersions[]
     | ((.versionStatus // .status) | ascii_upcase | gsub("-"; "_")) as $status
     | select($status == "STANDARD_SUPPORT" or $status == "EXTENDED_SUPPORT")
     | .clusterVersion]
    | sort_by(split(".") | map(tonumber))[]
' <<<"$versions_json")

catalog="$tmp/catalog.jsonl"
: >"$catalog"
for version in "${versions[@]}"; do
    metadata=$(aws ssm get-parameter \
        --name "/aws/service/eks/optimized-ami/$version/amazon-linux-2023/x86_64/standard/recommended" \
        --region "$REGION" --query Parameter.Value --output text)
    image_id=$(jq -er .image_id <<<"$metadata")
    image_name=$(jq -er .image_name <<<"$metadata")
    release_version=$(jq -er .release_version <<<"$metadata")
    [[ "$image_name" =~ -v([0-9]{8})$ ]] || { echo "unexpected AMI name: $image_name" >&2; exit 1; }

    tag="v${BASH_REMATCH[1]}"
    release="$tmp/$tag.body"
    [[ -s "$release" ]] || fetch_release_body "$tag" >"$release"
    kernel=$(kernel_from_release "$release" "$version")
    [[ -n "$kernel" ]] || { echo "kernel not found for Kubernetes $version in $tag" >&2; exit 1; }
    kernel_line=$(cut -d. -f1,2 <<<"$kernel")

    jq -cn \
        --arg kubernetes_version "$version" \
        --arg kernel_line "$kernel_line" \
        --arg kernel_version "$kernel" \
        --arg image_id "$image_id" \
        --arg release_version "$release_version" \
        '{kubernetes_version:$kubernetes_version,kernel_line:$kernel_line,
          kernel_version:$kernel_version,image_id:$image_id,
          release_version:$release_version}' >>"$catalog"
done

jq -s '
    group_by(.kernel_line)
    | map(min_by(.kubernetes_version | split(".") | map(tonumber)))
    | sort_by(.kernel_line | split(".") | map(tonumber))
' "$catalog"
