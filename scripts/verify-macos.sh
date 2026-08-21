#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"

usage() {
  echo "usage: $0 [--runtime-only]" >&2
  exit 2
}

[[ $# -le 1 ]] || usage
RUNTIME_ONLY=0
if [[ $# -eq 1 ]]; then
  [[ $1 == --runtime-only ]] || usage
  RUNTIME_ONLY=1
fi

[[ $(uname -s) == Darwin ]] || {
  echo "verify-macos: must run on macOS" >&2
  exit 69
}
[[ -x /usr/bin/sandbox-exec ]] || {
  echo "verify-macos: /usr/bin/sandbox-exec is unavailable" >&2
  exit 69
}
for command in cargo rustc; do
  command -v "$command" >/dev/null || {
    echo "verify-macos: $command is required" >&2
    exit 69
  }
done

SEATBELT_SELF_TEST='(version 1)(deny default)(allow file-read* file-read-metadata)(allow process-exec)(allow process-fork)(allow sysctl-read)(allow mach-lookup)(allow signal (target self))'
if ! /usr/bin/sandbox-exec -p "$SEATBELT_SELF_TEST" -- /usr/bin/true; then
  echo "verify-macos: Seatbelt functional probe failed" >&2
  exit 69
fi
echo "seatbelt functional probe: PASS"

if (( ! RUNTIME_ONLY )); then
  ./scripts/static-check.sh
  ./scripts/macos/static-check.sh
  cargo fmt --check
  cargo check --all-targets --locked
  cargo clippy --all-targets --locked -- -D warnings
  cargo test --all-targets --locked
fi

MBOX="$ROOT/target/debug/mbox" \
PROBE="$ROOT/target/mbox-macos-sandbox-probe" \
  "$ROOT/tests/macos/contract.sh"
