#!/usr/bin/env -S -i PATH=/usr/bin:/bin LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 /bin/bash
set -euo pipefail

[[ ${MBOX_RELEASE_STARTUP_BOUNDARY-} == mbox-macos-sanitized-v1 ]] || {
  printf 'static-check: direct bash invocation is unsupported; use the executable path\n' >&2
  exit 69
}

SCRIPT_DIR=$(/usr/bin/dirname "${BASH_SOURCE[0]}")
if [[ "$([ -x /usr/bin/uname ] && /usr/bin/uname -s)" == Darwin ]]; then
  # shellcheck source=scripts/macos/release-tools.sh
  source "$SCRIPT_DIR/macos/release-tools.sh"
  export PATH="$MBOX_RELEASE_SYSTEM_PATH"
  export MBOX_RELEASE_BASH_PATH=/bin/bash
else
  MBOX_RELEASE_BASH_PATH=/bin/bash
  MBOX_RELEASE_ENV_PATH=/usr/bin/env
  MBOX_RELEASE_SYSTEM_PATH=/usr/bin:/bin
fi

ROOT=$(cd "$SCRIPT_DIR/.." && /bin/pwd -P)
cd "$ROOT"

fail() {
  echo "static-check: $*" >&2
  exit 1
}

if [[ -e .github/workflows ]]; then
  fail ".github/workflows is out of scope"
fi

for path in \
  Cargo.toml Cargo.lock README.md docs/CONTRACT.md \
  src/main.rs src/cli.rs src/plan.rs src/platform/mod.rs \
  src/platform/fd.rs src/platform/linux.rs src/platform/seccomp.rs \
  src/platform/macos.rs src/platform/macos_proxy.rs \
  src/platform/macos_base.sbpl src/platform/macos_platform.sbpl \
  tests/linux/contract.sh tests/linux/helpers/sandbox_probe.rs \
  tests/macos/contract.sh tests/macos/helpers/sandbox_probe.rs; do
  [[ -f $path ]] || fail "missing $path"
done

[[ $(grep -c '^\[\[package\]\]' Cargo.lock) -eq 1 ]] || fail "Cargo.lock must contain only mbox"
if grep -Eq '^\[(build-)?dependencies([^]]*)?\]' Cargo.toml; then
  fail "external Rust dependencies are not allowed"
fi

for token in \
  'ExecutionPlan::build' 'close_inherited' 'sandbox-exec' \
  '--ro-bind-fd' '--bind-fd' 'EXECUTABLE' 'TIOCSTI' 'TIOCLINUX' 'SYS_SENDMSG' \
  '--allow-net' '--deny-write' 'setup aborted'; do
  grep -Rqs -- "$token" src || fail "missing source contract token: $token"
done

for path in scripts/verify.sh scripts/verify-macos.sh scripts/static-check.sh \
  scripts/macos/release-check.sh scripts/macos/static-check.sh \
  tests/macos/contract.sh; do
  grep -q '^#!/usr/bin/env -S -i ' "$path" || \
    fail "release-critical shell entrypoint is missing the sanitized shebang: $path"
  grep -q 'MBOX_RELEASE_STARTUP_BOUNDARY=' "$path" || \
    fail "release-critical shell entrypoint is missing the startup boundary marker: $path"
done

grep -qF -- '--no-child-processes' src/cli.rs || fail 'missing strict child-process CLI surface'
grep -qF -- 'no_child_processes' src/plan.rs || fail 'missing strict plan propagation'

for path in src/main.rs src/platform/seccomp.rs tests/linux/helpers/sandbox_probe.rs; do
  grep -qF -- 'target_arch = "x86_64"' "$path" || \
    fail "missing x86_64 Linux support declaration in $path"
  grep -qF -- 'target_arch = "aarch64"' "$path" || \
    fail "missing aarch64 Linux support declaration in $path"
  if grep -qF -- 'riscv64' "$path"; then
    fail "unsupported riscv64 Linux surface detected in $path"
  fi
  grep -qF -- 'supports x86_64 and aarch64' "$path" || \
    fail "Linux architecture boundary message missing in $path"
done

if grep -RInE -- '--not-a-security-boundary|--unshare-user-try|no[_-]sandbox|allow[_-]all' src; then
  fail "fail-open or compatibility bypass detected"
fi
if grep -RInE 'Command::(output|status|spawn).*plan\.program' src; then
  fail "target supervision/capture path detected"
fi

/usr/bin/find scripts tests -type f -name '*.sh' -print0 | /usr/bin/sort -z |
  /usr/bin/xargs -0 -n1 "$MBOX_RELEASE_ENV_PATH" -i \
    PATH="$MBOX_RELEASE_SYSTEM_PATH" HOME=/Users/ax LC_ALL=C \
    MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 \
    "$MBOX_RELEASE_BASH_PATH" -n

grep -qE 'expect_status 125 .*--allow-net' tests/linux/contract.sh || \
  fail 'missing Linux --allow-net setup-125 source coverage'
grep -qE 'expect_status 125 .*--deny-write' tests/linux/contract.sh || \
  fail 'missing Linux --deny-write setup-125 source coverage'
grep -qE 'expect_status 125 .*--no-child-processes' tests/linux/contract.sh || \
  fail 'missing Linux --no-child-processes setup-125 source coverage'

if [[ -f MANIFEST.sha256 ]]; then
  if [[ "$([ -x /usr/bin/uname ] && /usr/bin/uname -s)" == Darwin ]]; then
    /sbin/sha256sum -c MANIFEST.sha256 >/dev/null || fail "MANIFEST.sha256 mismatch"
  else
    /usr/bin/sha256sum -c MANIFEST.sha256 >/dev/null || fail "MANIFEST.sha256 mismatch"
  fi
fi

echo "static-check: PASS"
