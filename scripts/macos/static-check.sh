#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"

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
test -x scripts/verify-macos.sh
test -x tests/macos/contract.sh
test -f tests/macos/helpers/sandbox_probe.rs

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

command -v rustc >/dev/null
mkdir -p "$ROOT/target"
rustc --edition=2021 tests/macos/helpers/sandbox_probe.rs \
  -o "$ROOT/target/mbox-macos-sandbox-probe"
if command -v rustfmt >/dev/null; then
  rustfmt --edition 2021 --check tests/macos/helpers/sandbox_probe.rs
fi

echo "macos static-check: PASS"
