#!/usr/bin/env -S -i PATH=/usr/bin:/bin HOME=/Users/ax LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 /bin/bash
set -euo pipefail

[[ ${MBOX_RELEASE_STARTUP_BOUNDARY-} == mbox-macos-sanitized-v1 ]] || {
  printf 'verify-macos: direct bash invocation is unsupported; use the executable path\n' >&2
  exit 69
}
TMPDIR=$(/usr/bin/getconf DARWIN_USER_TEMP_DIR) || exit 69
export TMPDIR
[[ -d "$TMPDIR" && ! -L "$TMPDIR" ]] || exit 69

SCRIPT_DIR=$(/usr/bin/dirname "${BASH_SOURCE[0]}")
# shellcheck source=scripts/macos/release-tools.sh
source "$SCRIPT_DIR/macos/release-tools.sh"
export PATH="$MBOX_RELEASE_SYSTEM_PATH"
export LC_ALL=C

ROOT=$(cd "$SCRIPT_DIR/.." && "$MBOX_RELEASE_PWD_PATH" -P)
cd "$ROOT"

usage() {
  echo "usage: $0 [--runtime-only|--release-provenance]" >&2
  exit 2
}

[[ $# -le 1 ]] || usage
RUNTIME_ONLY=0
if [[ $# -eq 1 ]]; then
  case "$1" in
    --runtime-only) RUNTIME_ONLY=1 ;;
    --release-provenance)
      mbox_release_run_script "$ROOT/scripts/macos/release-check.sh"
      exit $?
      ;;
    *) usage ;;
  esac
fi

[[ $($MBOX_RELEASE_UNAME_PATH -s) == Darwin ]] || {
  echo "verify-macos: must run on macOS" >&2
  exit 69
}
[[ -x /usr/bin/sandbox-exec ]] || {
  echo "verify-macos: /usr/bin/sandbox-exec is unavailable" >&2
  exit 69
}
mbox_release_root_tool /usr/bin/sandbox-exec || exit 69
export MBOX_RELEASE_PROVENANCE=0
export HOME=/Users/ax
export RUSTUP_HOME=/Users/ax/.rustup
mbox_release_discover_toolchain || exit 69
export MBOX_RELEASE_PROVENANCE=1
export RUSTC="$MBOX_RELEASE_RUSTC_PATH"
export RUSTC_LINKER="$MBOX_RELEASE_CLANG_PATH"
SDKROOT_RAW=$("$MBOX_RELEASE_XCRUN_PATH" --sdk macosx --show-sdk-path)
export SDKROOT=$("$MBOX_RELEASE_REALPATH_PATH" "$SDKROOT_RAW")

SEATBELT_SELF_TEST='(version 1)(deny default)(allow file-read* file-read-metadata)(allow process-exec)(allow process-fork)(allow sysctl-read)(allow mach-lookup)(allow signal (target self))'
if ! /usr/bin/sandbox-exec -p "$SEATBELT_SELF_TEST" -- /usr/bin/true; then
  echo "verify-macos: Seatbelt functional probe failed" >&2
  exit 69
fi
echo "seatbelt functional probe: PASS"

if (( ! RUNTIME_ONLY )); then
  mbox_release_run_script "$ROOT/scripts/static-check.sh"
  mbox_release_run_script "$ROOT/scripts/macos/static-check.sh"
  mbox_release_run_cargo fmt --check
  mbox_release_run_cargo check --all-targets --locked
  mbox_release_run_cargo clippy --all-targets --locked -- -D warnings
  mbox_release_run_cargo test --all-targets --locked
fi

mbox_release_run_cargo build --quiet --locked

MBOX="$ROOT/target/debug/mbox" \
PROBE="$ROOT/target/mbox-macos-sandbox-probe" \
  mbox_release_run_script "$ROOT/tests/macos/contract.sh"
