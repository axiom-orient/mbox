#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"

fail() {
  echo "linux static-check: $*" >&2
  exit 1
}

[[ $(uname -s) == Linux ]] || {
  echo "linux static-check: must run on Linux" >&2
  exit 69
}

for path in \
  docs/LINUX_VERIFICATION.md docs/linux/CONTRACT.md docs/linux/SCENARIOS.md \
  scripts/verify-linux.sh tests/linux/contract.sh \
  tests/linux/helpers/sandbox_probe.rs; do
  [[ -f $path ]] || fail "missing $path"
done

for token in \
  'MIN_BWRAP_VERSION' 'Version::new(0, 10, 0)' \
  '--ro-bind-fd' '--bind-fd' 'O_PATH' 'O_NOFOLLOW' \
  '--disable-userns' '--unshare-pid' '--die-with-parent' \
  'TIOCSTI' 'TIOCLINUX' 'SYS_SOCKET' 'SYS_SENDMSG' 'SYS_RECVMSG'; do
  grep -Rqs -- "$token" src/platform/linux.rs src/platform/seccomp.rs || \
    fail "missing Linux contract token: $token"
done

if grep -nE '^[[:space:]]*push\(&mut args, "--new-session"\);' src/platform/linux.rs; then
  fail "--new-session changes the foreground terminal contract"
fi
if grep -nE '^[[:space:]]*"/etc",?[[:space:]]*$' src/platform/linux.rs; then
  fail "ambient full /etc mount detected"
fi
if grep -nE '^[[:space:]]*"/usr",?[[:space:]]*$|^[[:space:]]*"/usr/local(/|")' src/platform/linux.rs; then
  fail "ambient full /usr or /usr/local mount detected"
fi
if grep -nE '/proc/\$?\{?descendant|kill -0.*descendant' tests/linux/contract.sh; then
  fail "namespace PID used as a host cancellation oracle"
fi
grep -q 'hold-lock' tests/linux/contract.sh || fail "missing lock cancellation oracle"
grep -q 'try-lock' tests/linux/contract.sh || fail "missing lock release assertion"
grep -q 'userns-disabled' tests/linux/contract.sh || fail "missing nested-userns regression"
grep -q 'pass AA' tests/linux/contract.sh || fail "missing exact executable regression"
grep -q 'rename-file' tests/linux/contract.sh || fail "missing executable replacement regression"
grep -q 'unix-socketpair' tests/linux/contract.sh || fail "missing anonymous IPC regression"
grep -q 'unix-dgram-sendto' tests/linux/contract.sh || fail "missing pathname-socket send regression"
grep -q 'tty-query' tests/linux/contract.sh || fail "missing ordinary ioctl regression"
grep -q 'restrict_sendto_destination' src/platform/seccomp.rs || fail "missing conditional sendto filter"
grep -q 'writable_descendant_is_mounted_after_readable_parent' src/platform/linux.rs || \
  fail "missing parent-read/child-write mount-order regression"
grep -q 'Reassert the exact executable as read-only' src/platform/linux.rs || \
  fail "missing exact executable pin after writable parents"

grep -qF -- 'TEST_TMP_BASE=${MBOX_TEST_TMPDIR:-/var/tmp}' tests/linux/contract.sh || \
  fail "contract fixture must default outside sandbox-private scratch"
grep -qF -- 'readlink -f --' tests/linux/contract.sh || \
  fail "contract fixture root must be canonicalized"
grep -qF -- '/tmp|/tmp/*|/dev/shm|/dev/shm/*' tests/linux/contract.sh || \
  fail "contract fixture must reject sandbox-private scratch roots"
if grep -qF -- 'mktemp -d "${TMPDIR:-/tmp}/mbox-contract.' tests/linux/contract.sh; then
  fail "contract fixture must not use TMPDIR or sandbox-private /tmp"
fi

command -v rustc >/dev/null 2>&1 || {
  echo "linux static-check: rustc is required" >&2
  exit 69
}
mkdir -p target
rustc --edition=2021 tests/linux/helpers/sandbox_probe.rs \
  -o target/mbox-linux-sandbox-probe.static
rm -f target/mbox-linux-sandbox-probe.static
if command -v rustfmt >/dev/null; then
  rustfmt --edition 2021 --check tests/linux/helpers/sandbox_probe.rs
fi

echo "linux static-check: PASS"
