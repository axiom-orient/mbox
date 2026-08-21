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

[[ $(uname -s) == Linux ]] || {
  echo "verify-linux: must run on Linux" >&2
  exit 69
}
for command in cargo rustc; do
  command -v "$command" >/dev/null || {
    echo "verify-linux: $command is required" >&2
    exit 69
  }
done

validate_trusted_bwrap() {
  local path=$1 owner mode numeric parent
  [[ -f $path && -x $path ]] || return 1
  read -r owner mode < <(stat -Lc '%u %a' "$path") || return 1
  [[ $owner == 0 ]] || return 1
  numeric=$((8#$mode))
  (( (numeric & 0111) != 0 )) || return 1
  (( (numeric & 0022) == 0 )) || return 1
  (( (numeric & 06000) == 0 )) || return 1

  parent=$(dirname "$path")
  while :; do
    read -r owner mode < <(stat -Lc '%u %a' "$parent") || return 1
    [[ $owner == 0 && -d $parent ]] || return 1
    numeric=$((8#$mode))
    (( (numeric & 0022) == 0 )) || return 1
    [[ $parent == / ]] && break
    parent=$(dirname "$parent")
  done
}

BWRAP=
for candidate in /usr/bin/bwrap /bin/bwrap; do
  [[ -e $candidate ]] || continue
  BWRAP=$(readlink -f "$candidate") || {
    echo "verify-linux: cannot canonicalize Bubblewrap: $candidate" >&2
    exit 69
  }
  validate_trusted_bwrap "$BWRAP" || {
    echo "verify-linux: Bubblewrap is not a trusted non-setuid root-owned executable: $BWRAP" >&2
    exit 69
  }
  break
done
[[ -n $BWRAP ]] || {
  echo "verify-linux: trusted Bubblewrap is unavailable" >&2
  exit 69
}

version_text=$(LC_ALL=C "$BWRAP" --version 2>/dev/null) || {
  echo "verify-linux: Bubblewrap could not report its version" >&2
  exit 69
}
if [[ $version_text =~ ([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
  major=${BASH_REMATCH[1]}
  minor=${BASH_REMATCH[2]}
  patch=${BASH_REMATCH[3]}
else
  echo "verify-linux: unrecognized Bubblewrap version: $version_text" >&2
  exit 69
fi
if (( major == 0 && minor < 10 )); then
  echo "verify-linux: Bubblewrap 0.10.0 or newer is required; found $major.$minor.$patch" >&2
  exit 69
fi

if (( ! RUNTIME_ONLY )); then
  ./scripts/static-check.sh
  ./scripts/linux/static-check.sh
  cargo fmt --check
  cargo check --all-targets --locked
  cargo clippy --all-targets --locked -- -D warnings
  cargo test --all-targets --locked
fi

cargo build --quiet --locked

# Verify the exact minimum feature set and host namespace support before the
# product contract. This is an environment gate, not sandbox security proof.
exec {root_fd}< /
set +e
"$BWRAP" \
  --die-with-parent \
  --unshare-user --disable-userns \
  --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
  --cap-drop ALL --clearenv \
  --ro-bind-fd "$root_fd" / \
  --proc /proc --dev /dev --tmpfs /tmp \
  --argv0 true -- /usr/bin/true \
  >"$ROOT/target/mbox-bwrap-probe.stdout" \
  2>"$ROOT/target/mbox-bwrap-probe.stderr"
probe_status=$?
set -e
exec {root_fd}<&-
if [[ $probe_status -ne 0 ]]; then
  cat "$ROOT/target/mbox-bwrap-probe.stderr" >&2 || true
  echo "verify-linux: Bubblewrap feature/user-namespace probe failed" >&2
  exit 69
fi

MBOX="$ROOT/target/debug/mbox" \
PROBE="$ROOT/target/mbox-linux-sandbox-probe" \
  "$ROOT/tests/linux/contract.sh"
