#!/usr/bin/env bash
set -euo pipefail

DIR=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

cat >"$tmp/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "eks describe-cluster-versions" ]]; then
    # Extended-support versions must not depend on the API's default
    # filtering: require the explicit --include-all flag.
    [[ " $* " == *" --include-all "* ]] \
        || { echo "describe-cluster-versions called without --include-all" >&2; exit 1; }
    cat <<'JSON'
{"clusterVersions":[
 {"clusterVersion":"1.36","versionStatus":"STANDARD_SUPPORT"},
 {"clusterVersion":"1.34","status":"standard-support"},
 {"clusterVersion":"1.33","status":"extended-support"},
 {"clusterVersion":"1.32","versionStatus":"EXTENDED_SUPPORT"},
 {"clusterVersion":"1.30","versionStatus":"UNSUPPORTED"}]}
JSON
elif [[ "$1 $2" == "ssm get-parameter" ]]; then
    while [[ $# -gt 0 ]]; do
        [[ "$1" == "--name" ]] && { name="$2"; break; }
        shift
    done
    version=$(sed -n 's#.*optimized-ami/\([0-9]*\.[0-9]*\)/.*#\1#p' <<<"$name")
    [[ "$version" != "1.30" ]] || exit 1
    printf '{"image_id":"ami-%s","image_name":"amazon-eks-node-al2023-x86_64-standard-%s-v20260818","release_version":"%s-test"}\n' \
        "${version/./}" "$version" "$version"
else
    echo "unexpected aws command: $*" >&2; exit 1
fi
EOF
chmod +x "$tmp/bin/aws"

cat >"$tmp/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Mock of the GitHub Releases API. Validates the request contract (URL,
# Accept header, Authorization presence tracking MOCK_EXPECT_AUTH), then
# emits {"body": "<release notes markup>"} like the real API.
url="" accept="" auth=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -H) case "$2" in
                Accept:*) accept="$2" ;;
                Authorization:*) auth="$2" ;;
            esac; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
[[ "$url" == "https://api.github.com/repos/awslabs/amazon-eks-ami/releases/tags/v20260818" ]] \
    || { echo "unexpected URL: $url" >&2; exit 1; }
[[ -n "$accept" ]] || { echo "missing Accept header" >&2; exit 1; }
if [[ "${MOCK_EXPECT_AUTH:-}" == "1" ]]; then
    [[ "$auth" == "Authorization: Bearer test-token" ]] \
        || { echo "expected Authorization header, got: $auth" >&2; exit 1; }
else
    [[ -z "$auth" ]] || { echo "unexpected Authorization header: $auth" >&2; exit 1; }
fi
if [[ "${MOCK_MODE:-}" == "rate_limit" ]]; then
    printf '{"message":"API rate limit exceeded","documentation_url":"https://docs.github.com"}\n'
    exit 0
fi
header() {
    cat <<'HTML'
<tr>
<th>Package</th>
<th>AL2023_x86_64_NVIDIA</th>
<th>AL2023_x86_64_NEURON</th>
<th>AL2023_x86_64_STANDARD</th>
<th>AL2023_ARM_64_NVIDIA</th>
<th>AL2023_ARM_64_STANDARD</th>
</tr>
HTML
}
{
    echo '<summary><b>Kubernetes 1.36</b></summary>'; header
    cat <<'HTML'
<tr><td>kernel6.18</td>
<td colspan="2">9.9.9-wrong-variant</td>
<td>6.18.41-94.142.amzn2023</td>
<td colspan="2">8.8.8-other-variant</td>
</tr>
HTML
    echo '<summary><b>Kubernetes 1.34</b></summary>'; header
    printf '<tr><td>kernel6.12</td>\n<td colspan="5">6.12.100-125.179.amzn2023</td>\n</tr>\n'
    echo '<summary><b>Kubernetes 1.33</b></summary>'; header
    printf '<tr><td>kernel6.12</td>\n<td colspan="5">6.12.99-1.amzn2023</td>\n</tr>\n'
    echo '<summary><b>Kubernetes 1.32</b></summary>'; header
    printf '<tr><td>kernel</td>\n<td colspan="3">6.1.180-225.360.amzn2023</td>\n</tr>\n'
} | jq -Rs '{body: .}'
EOF
chmod +x "$tmp/bin/curl"

assert_matrix() {
    jq -e '
        map(.kernel_line) == ["6.1","6.12","6.18"] and
        map(.kubernetes_version) == ["1.32","1.33","1.36"] and
        .[1].kernel_version == "6.12.99-1.amzn2023"
    ' <<<"$1" >/dev/null
}

# Unauthenticated: no Authorization header may be sent.
result=$(PATH="$tmp/bin:$PATH" GITHUB_TOKEN="" "$DIR/run.sh")
assert_matrix "$result"
echo "PASS: kernel matrix discovery (unauthenticated)"

# Authenticated: the token must arrive as a Bearer Authorization header.
result=$(PATH="$tmp/bin:$PATH" GITHUB_TOKEN=test-token MOCK_EXPECT_AUTH=1 "$DIR/run.sh")
assert_matrix "$result"
echo "PASS: kernel matrix discovery (authenticated)"

# API error: discovery must fail and surface the API message.
if err=$(PATH="$tmp/bin:$PATH" GITHUB_TOKEN="" MOCK_MODE=rate_limit "$DIR/run.sh" 2>&1); then
    echo "FAIL: expected discovery to fail on API error" >&2; exit 1
fi
grep -q "API rate limit exceeded" <<<"$err" \
    || { echo "FAIL: API error message not surfaced: $err" >&2; exit 1; }
echo "PASS: API error surfaced"
