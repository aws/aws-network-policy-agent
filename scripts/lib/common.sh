#!/usr/bin/env bash

check_is_installed() {
    local __name="$1"
    if ! is_installed "$__name"; then
        echo "Please install $__name before running this script."
        exit 1
    fi
}

is_installed() {
    local __name="$1"
    if $(which $__name >/dev/null 2>&1); then
        return 0
    else
        return 1
    fi
}

# Errors that come from the API server or the path to it rather than from the request
# itself, e.g. a 401 when the authenticator's STS call times out, dropped connections
# and 5xx responses. Anything else (NotFound, Forbidden, AlreadyExists) is returned as-is.
KUBECTL_TRANSIENT_ERRORS='Unauthorized|You must be logged in|i/o timeout|TLS handshake timeout|context deadline exceeded|Client.Timeout|timed out|Timeout:|connection refused|connection reset|broken pipe|unexpected EOF|EOF$|http2:|InternalError|Internal error occurred|ServiceUnavailable|Service Unavailable|the server is currently unable|TooManyRequests|Too many requests|etcdserver|the object has been modified'

# kubectl_retry <kubectl args...>
# Runs kubectl with a per-request timeout and retries transient errors until
# KUBECTL_RETRY_BUDGET seconds (default 600) have passed, KUBECTL_RETRY_DELAY seconds
# (default 10) apart. Only the successful attempt's stdout is written; on failure the
# last attempt's exit code is returned.
function kubectl_retry() {
  local budget=${KUBECTL_RETRY_BUDGET:-600} delay=${KUBECTL_RETRY_DELAY:-10}
  local deadline=$(( $(date +%s) + budget )) attempt=0 rc out err
  out=$(mktemp)
  err=$(mktemp)
  while true; do
    attempt=$((attempt + 1))
    rc=0
    kubectl --request-timeout="${KUBECTL_REQUEST_TIMEOUT:-60s}" "$@" > "$out" 2> "$err" || rc=$?
    cat "$err" >&2
    if [ "$rc" -eq 0 ]; then
      cat "$out"
      break
    fi
    if ! grep -qE "$KUBECTL_TRANSIENT_ERRORS" "$err"; then
      break
    fi
    if [ $(( $(date +%s) + delay )) -ge "$deadline" ]; then
      echo "kubectl $1: giving up after ${attempt} attempts (${budget}s budget), exit ${rc}" >&2
      break
    fi
    echo "kubectl $1: transient error on attempt ${attempt} (exit ${rc}), retrying in ${delay}s" >&2
    sleep "$delay"
  done
  rm -f "$out" "$err"
  return "$rc"
}
