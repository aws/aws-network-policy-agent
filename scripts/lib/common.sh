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

function kubectl_retry() {
  local attempts=${KUBECTL_RETRIES:-5} delay=${KUBECTL_RETRY_DELAY:-10} i
  for ((i = 1; i <= attempts; i++)); do
    local out
    if out=$(kubectl "$@"); then
      printf '%s\n' "$out"
      return 0
    fi
    echo "kubectl $* failed (attempt ${i}/${attempts}), retrying in ${delay}s" >&2
    sleep "$delay"
  done
  return 1
}
