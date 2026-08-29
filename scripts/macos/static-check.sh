#!/usr/bin/env -S -i PATH=/usr/bin:/bin HOME=/Users/ax LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 /bin/bash
set -euo pipefail

[[ ${MBOX_RELEASE_STARTUP_BOUNDARY-} == mbox-macos-sanitized-v1 ]] || {
  printf 'macos static-check: direct bash invocation is unsupported; use the executable path\n' >&2
  exit 69
}
TMPDIR=$(/usr/bin/getconf DARWIN_USER_TEMP_DIR) || exit 69
export TMPDIR
[[ -d "$TMPDIR" && ! -L "$TMPDIR" ]] || exit 69

SCRIPT_DIR=$(/usr/bin/dirname "${BASH_SOURCE[0]}")
# shellcheck source=scripts/macos/release-tools.sh
source "$SCRIPT_DIR/release-tools.sh"
export PATH="$MBOX_RELEASE_SYSTEM_PATH"
export LC_ALL=C

if [[ "${MBOX_RELEASE_PROVENANCE:-0}" != 1 ]]; then
  export MBOX_RELEASE_PROVENANCE=0
  export HOME=/Users/ax
  export RUSTUP_HOME=/Users/ax/.rustup
  mbox_release_discover_toolchain
  export MBOX_RELEASE_PROVENANCE=1
fi

ROOT=$(cd "$SCRIPT_DIR/../.." && "$MBOX_RELEASE_PWD_PATH" -P)
cd "$ROOT"

fail() {
  echo "macos static-check: $*" >&2
  exit 1
}

[[ $(uname -s) == Darwin ]] || {
  echo "macos static-check: must run on macOS" >&2
  exit 69
}

test -f Cargo.toml
test -f Cargo.lock
test -f AGENTS.md
test -f README.md
test -f src/main.rs
test -f src/plan.rs
test -f src/platform/macos.rs
test -f src/platform/macos_proxy.rs
test -f src/platform/macos_base.sbpl
test -f src/platform/macos_platform.sbpl
test -f docs/MACOS_VERIFICATION.md
test -f docs/macos/README.md
test -f docs/macos/CONTRACT.md
test -f docs/macos/SCENARIOS.md
test -f docs/macos/RELEASE-v0.2.0.sha256
test -f scripts/macos/atomic_install.rs
test -f scripts/macos/release-tools.sh
grep -Eq '^sha256=[0-9a-f]{64}$' docs/macos/RELEASE-v0.2.0.sha256
test -x scripts/verify-macos.sh
test -x scripts/macos/release-check.sh
test -x tests/macos/contract.sh
test -f tests/macos/helpers/sandbox_probe.rs

for path in \
  scripts/verify.sh scripts/verify-macos.sh scripts/static-check.sh \
  scripts/macos/release-check.sh scripts/macos/static-check.sh \
  tests/macos/contract.sh; do
  grep -q '^#!/usr/bin/env -S -i ' "$path" || \
    fail "release-critical entrypoint lacks the pre-Bash env -S -i boundary: $path"
  grep -q 'MBOX_RELEASE_STARTUP_BOUNDARY=' "$path" || \
    fail "release-critical entrypoint lacks the startup boundary marker: $path"
done
grep -q 'mbox_release_run_script' scripts/macos/release-tools.sh || \
  fail 'missing sanitized nested-script runner'
for token in BASH_ENV ENV SHELLOPTS BASHOPTS CDPATH GLOBIGNORE BASH_XTRACEFD; do
  grep -q "$token" scripts/macos/release-check.sh scripts/macos/release-tools.sh || \
    fail "missing hostile startup variable regression: $token"
done
if grep -nE '\$MBOX_RELEASE_BASH_PATH.*(scripts/static-check|scripts/macos/static-check|tests/macos/contract|release-check)' \
  scripts/verify-macos.sh scripts/macos/release-check.sh; then
  fail 'nested release scripts bypass the sanitized runner'
fi

for field in protocol version host arch rustc cargo rustc-path rustc-sha256 cargo-path cargo-sha256 \
  rustfmt-path rustfmt-sha256 clippy-driver-path clippy-driver-sha256 linker-path linker-sha256 \
  sdk-path xcrun-path xcrun-sha256 hash-path hash-sha256 hash-verify-path hash-verify-sha256 \
  source-fingerprint release-helper-sha256 release-helper-binary-sha256 \
  build-root build-path install-path build-command repeatability verification sha256; do
  grep -q "^${field}=" docs/macos/RELEASE-v0.2.0.sha256 || \
    fail "missing release provenance field: $field"
done
grep -q 'mbox-macos-fixed-release-v2' scripts/macos/release-check.sh
grep -q 'CANONICAL_TARGET="\$CANONICAL_REPO/target"' scripts/macos/release-check.sh
grep -q 'RESERVED_BUILD_NAME=".mbox-release-v2"' scripts/macos/release-check.sh
grep -q 'RESERVED_MARKER=' scripts/macos/release-check.sh
grep -q 'assert_no_symlink_components' scripts/macos/release-check.sh
grep -q 'assert_owned_directory' scripts/macos/release-check.sh
grep -q 'assert_owned_regular_file' scripts/macos/release-check.sh
grep -q 'assert_reserved_tree_safe' scripts/macos/release-check.sh
grep -q '\-P -x' scripts/macos/release-check.sh
grep -q 'prepare_install_directory' scripts/macos/release-check.sh
grep -q 'compile_atomic_install_helper' scripts/macos/release-check.sh
grep -q 'atomic_install_self_test' scripts/macos/release-check.sh
grep -q 'ATOMIC_INSTALL_SOURCE' scripts/macos/release-check.sh
grep -q 'release-helper-sha256' scripts/macos/release-check.sh
grep -q 'release-helper-binary-sha256' scripts/macos/release-check.sh
grep -q 'cargo-path' scripts/macos/release-check.sh
grep -q 'rustc-path' scripts/macos/release-check.sh
grep -q 'MBOX_RELEASE_PROVENANCE' scripts/macos/release-check.sh
grep -q 'MBOX_RELEASE_CARGO_PATH' scripts/macos/release-tools.sh
grep -q 'mbox_release_recheck_tool' scripts/macos/release-tools.sh
grep -q 'RUSTC_LINKER' scripts/macos/release-check.sh
grep -q 'SDKROOT' scripts/macos/release-check.sh
grep -q 'PATH="$MBOX_RELEASE_SYSTEM_PATH"' scripts/macos/release-check.sh
grep -q '/bin/bash' scripts/macos/release-check.sh
if grep -nE '^#! */usr/bin/env bash|(^|[[:space:]])command -v[[:space:]]' \
  scripts/macos/release-check.sh scripts/macos/release-tools.sh scripts/verify-macos.sh \
  scripts/macos/static-check.sh tests/macos/contract.sh; then
  fail "release protocol resolves bash or toolchain through ambient PATH"
fi
grep -q 'openat' scripts/macos/atomic_install.rs
grep -q 'O_NOFOLLOW' scripts/macos/atomic_install.rs
grep -q 'O_EXCL' scripts/macos/atomic_install.rs
grep -q 'fstat' scripts/macos/atomic_install.rs
grep -q 'renameat' scripts/macos/atomic_install.rs
grep -q 'fsync' scripts/macos/atomic_install.rs
grep -q 'unlinkat' scripts/macos/atomic_install.rs
if grep -n 'cp -p -- "$FIRST_ARTIFACT" "$CANONICAL_BIN"' scripts/macos/release-check.sh; then
  fail "final release install must use the audited native helper"
fi
grep -q 'install-path' scripts/macos/release-check.sh
grep -q 'MAX_RECORD_LINES' scripts/macos/release-check.sh
grep -q 'reject_unsafe_record_value' scripts/macos/release-check.sh
grep -q 'rewrite_record_field' scripts/macos/release-check.sh
grep -q 'stale release-helper-sha256' scripts/macos/release-check.sh
if grep -nE '(^|[[:space:]])eval([[:space:]]|$)|fail[[:space:]].*record_(host|arch|rustc|cargo|source_fingerprint|build_root|build_path|install_path|build_command|repeatability|verification|sha256)' scripts/macos/release-check.sh; then
  fail "release provenance parser contains shell-evaluation or untrusted command-substitution syntax"
fi
if grep -nE 'rm[[:space:]]+-rf[^\n]*CANONICAL_TARGET|safe_clean_canonical_target' scripts/macos/release-check.sh; then
  fail "release protocol deletes the entire canonical target"
fi
grep -q 'two-sequential-clean-builds-at-canonical-root' scripts/macos/release-check.sh
grep -q -- '--check-record' scripts/macos/release-check.sh
grep -q -- '--self-test' scripts/macos/release-check.sh
grep -q 'source_input_list' scripts/macos/release-check.sh
grep -q 'unexpected Cargo config input' scripts/macos/release-check.sh
grep -q 'unexpected toolchain input' scripts/macos/release-check.sh
grep -q 'MBOX_RELEASE_CMP_PATH' scripts/macos/release-check.sh
grep -q 'FIRST_ARTIFACT' scripts/macos/release-check.sh
grep -q 'complete contract A-AQ+AE' scripts/macos/release-check.sh
if grep -nE 'target-one|target-two|fresh-temporary-directory|independent clean release' \
  scripts/macos/release-check.sh docs/MACOS_VERIFICATION.md docs/macos/README.md; then
  fail "obsolete path-independent or separate-target release protocol detected"
fi

grep -q 'target_os = "macos"' src/platform/mod.rs
grep -q 'sandbox-exec' src/platform/macos.rs
grep -q 'validate_private_tmp' src/platform/macos.rs
grep -q 'path-ancestors (param' src/platform/macos.rs
grep -q -- '--tmp' src/cli.rs
if grep -nE 'create_private_scratch|\.mbox-' src/platform/macos.rs; then
  echo "macos static-check: automatic scratch allocation detected" >&2
  exit 1
fi
grep -q '(deny default)' src/platform/macos_base.sbpl
grep -q '(ioctl-command #x80017472)' src/platform/macos.rs
grep -q 'param "EXECUTABLE"' src/platform/macos.rs
grep -q 'deny file-write\*' src/platform/macos.rs
grep -q -- '--allow-net' src/cli.rs
grep -q -- '--deny-write' src/cli.rs
grep -q -- '--no-child-processes' src/cli.rs
grep -q 'validate_native_executable' src/platform/macos.rs
grep -q 'read_at' src/platform/macos.rs
grep -q 'MAX_FAT_ARCHES' src/platform/macos.rs
grep -q 'on-disk fat' src/platform/macos.rs
grep -q '32-bit Mach-O is not executable' src/platform/macos.rs
grep -q 'fat32-cigam' src/platform/macos.rs
grep -q 'fat64-cigam' src/platform/macos.rs
grep -q 'MAX_LOAD_COMMANDS' src/platform/macos.rs
grep -q 'MAX_LOAD_COMMAND_BYTES' src/platform/macos.rs
grep -q 'HOST_BYTE_ORDER' src/platform/macos.rs
grep -q 'LC_MAIN' src/platform/macos.rs
grep -q 'LC_UNIXTHREAD' src/platform/macos.rs
grep -q 'establish_process_group_leader' src/platform/macos.rs
grep -q '(deny process-fork)' src/platform/macos.rs
grep -q '(deny process-exec)' src/platform/macos.rs
grep -q 'with_process_group_leader' src/platform/mod.rs
grep -q 'ProxyRuntime' src/platform/macos.rs
grep -q 'process_group(0)' src/platform/macos.rs
grep -q 'WAIT_WNOWAIT' src/platform/macos.rs
grep -q 'sigprocmask' src/platform/macos.rs
grep -q 'close_inherited(&\[\])' src/platform/macos.rs
grep -q 'remote ip "localhost:' src/platform/macos.rs
grep -q 'MAX_CONNECTIONS' src/platform/macos_proxy.rs
grep -q 'MAX_RESOLVER_HELPERS' src/platform/macos_proxy.rs
grep -q 'ClientHelloParser' src/platform/macos_proxy.rs
grep -q 'MAX_TLS_CLIENT_HELLO_BYTES' src/platform/macos_proxy.rs
grep -q '0xfe0d' src/platform/macos_proxy.rs
grep -q 'recv_timeout' src/platform/macos_proxy.rs
grep -q 'file-link' src/platform/macos.rs
grep -q 'reject_hardlinks' src/plan.rs
grep -q 'unset HTTP_PROXY' tests/macos/contract.sh
grep -q 'proxy-hold' tests/macos/contract.sh
grep -q 'proxy-abuse' tests/macos/contract.sh
grep -q 'raw-dns' tests/macos/contract.sh
grep -q 'direct-public-ip' tests/macos/contract.sh
grep -q 'proxy-check6' tests/macos/contract.sh
grep -q 'tcp-bind6' tests/macos/contract.sh
grep -q 'process-fd-count' tests/macos/contract.sh
grep -q 'allow-net localhost' tests/macos/contract.sh
grep -q 'kill -INT' tests/macos/contract.sh
grep -q 'remove-dir' tests/macos/contract.sh
grep -q 'hardlink' tests/macos/contract.sh
grep -q 'AF-SNI' tests/macos/contract.sh
grep -q 'avatars.githubusercontent.com' tests/macos/contract.sh
grep -q 'deny-write' tests/macos/contract.sh
grep -q 'pass AD' tests/macos/contract.sh
grep -q 'setsid-escape' tests/macos/contract.sh
grep -q 'pass AJ' tests/macos/contract.sh
grep -q 'pass AK' tests/macos/contract.sh
grep -q 'pass AL' tests/macos/contract.sh
grep -q 'pass AM' tests/macos/contract.sh
grep -q 'pass AN' tests/macos/contract.sh
grep -q 'pass AO' tests/macos/contract.sh
grep -q 'pass AP' tests/macos/contract.sh
grep -q 'pass AQ' tests/macos/contract.sh
grep -q 'self-reexec' tests/macos/contract.sh
grep -q 'SELF-REEXEC-BEFORE' tests/macos/helpers/sandbox_probe.rs
grep -q 'SELF-REEXEC-AFTER' tests/macos/helpers/sandbox_probe.rs
grep -q 'execve' tests/macos/helpers/sandbox_probe.rs
grep -q -- '--release-provenance' scripts/verify-macos.sh
grep -q 'CARGO_TARGET_DIR' scripts/macos/release-check.sh
grep -q 'sequential clean builds=2 at one reserved path' scripts/macos/release-check.sh
grep -q 'complete contract A-AQ+AE=PASS' scripts/macos/release-check.sh
grep -q 'CIGAM32' tests/macos/contract.sh
grep -q 'CIGAM64' tests/macos/contract.sh
grep -q 'thread-only' tests/macos/helpers/sandbox_probe.rs
grep -q 'posix_spawn' tests/macos/helpers/sandbox_probe.rs
grep -q 'vfork' tests/macos/helpers/sandbox_probe.rs
grep -q 'rename-file' tests/macos/contract.sh
grep -q 'process_identity' tests/macos/contract.sh
grep -q 'process-identity' tests/macos/contract.sh
grep -q 'PROC_PIDTBSDINFO' tests/macos/helpers/sandbox_probe.rs
grep -q 'proc_pidinfo' tests/macos/helpers/sandbox_probe.rs
grep -q 'process-fd-count' tests/macos/helpers/sandbox_probe.rs
grep -q 'PROC_PIDLISTFDS' tests/macos/helpers/sandbox_probe.rs
grep -q 'ProcFdInfo' tests/macos/helpers/sandbox_probe.rs
grep -q 'UdpSocket' tests/macos/helpers/sandbox_probe.rs
grep -q 'proxy-abuse' tests/macos/helpers/sandbox_probe.rs
grep -q 'pbi_start_tvsec' tests/macos/helpers/sandbox_probe.rs
grep -q 'pbi_start_tvusec' tests/macos/helpers/sandbox_probe.rs
grep -q '#\[repr(C)\]' tests/macos/helpers/sandbox_probe.rs
grep -q 'LIFECYCLE_POLL_LIMIT' tests/macos/contract.sh
grep -q 'cleanup_unidentified_server' tests/macos/contract.sh
grep -q 'IDENTITY_CAPTURE_FAIL_FAST' tests/macos/contract.sh
grep -q 'identity-mismatch' tests/macos/contract.sh
grep -q 'kill -TERM "$SERVER_PID"' tests/macos/contract.sh
grep -q 'kill -KILL "$SERVER_PID"' tests/macos/contract.sh
grep -q 'no survivor delayed' tests/macos/contract.sh
if grep -nE '(^|[[:space:]])(pkill|killall)([[:space:]]|$)|kill[[:space:]]+-[A-Z]+[[:space:]]+-' tests/macos/contract.sh; then
  echo "macos static-check: broad process cleanup detected" >&2
  exit 1
fi
if grep -RInE 'ps.*lstart|lstart' tests/macos docs/MACOS_VERIFICATION.md docs/macos/*.md; then
  echo "macos static-check: second-resolution ps lifecycle identity detected" >&2
  exit 1
fi
grep -q '(literal "/private/var/select/sh"))' src/platform/macos_platform.sbpl
grep -q '(path-ancestors "/usr/bin/sandbox-exec")' src/platform/macos_platform.sbpl
grep -q '(path-ancestors "/bin/bash")' src/platform/macos_platform.sbpl
if grep -nE 'file-read-data.*path-ancestors|file-read\*.*path-ancestors' src/platform/macos_platform.sbpl; then
  echo "macos static-check: data authority attached to launcher ancestor metadata" >&2
  exit 1
fi
if grep -nE '\(path-ancestors "/(usr|bin)"\)' src/platform/macos_platform.sbpl; then
  echo "macos static-check: broad launcher ancestor metadata detected" >&2
  exit 1
fi
if grep -nE '\(subpath "/(Applications|opt/homebrew|usr/local|usr)"\)|com\.apple\.app-sandbox\.(read|read-write)' src/platform/macos_platform.sbpl; then
  echo "macos static-check: ambient macOS filesystem authority detected" >&2
  exit 1
fi

if grep -RInE 'ptrace|io-uring|seccomp|Bubblewrap|/proc|V2' tests/macos; then
  echo "macos static-check: Linux-only contract surface detected" >&2
  exit 1
fi

if grep -nE 'tests/linux/|scripts/linux/|verify-linux\.sh' \
  scripts/verify-macos.sh docs/macos/*.md docs/MACOS_VERIFICATION.md; then
  echo "macos static-check: mixed or Linux verifier referenced" >&2
  exit 1
fi

bash -n scripts/macos/static-check.sh
bash -n scripts/verify-macos.sh
bash -n tests/macos/contract.sh

mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$MBOX_RELEASE_RUSTC_SHA256"
$MBOX_RELEASE_MKDIR_PATH -p "$ROOT/target"
"$MBOX_RELEASE_RUSTC_PATH" --edition=2021 tests/macos/helpers/sandbox_probe.rs \
  -o "$ROOT/target/mbox-macos-sandbox-probe"
mbox_release_recheck_tool rustfmt "$MBOX_RELEASE_RUSTFMT_PATH" "$MBOX_RELEASE_RUSTFMT_SHA256"
"$MBOX_RELEASE_RUSTFMT_PATH" --edition 2021 --check tests/macos/helpers/sandbox_probe.rs

echo "macos static-check: PASS"
