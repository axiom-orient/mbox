# Linux verification

Run from the repository root:

```sh
set -o pipefail
log=$(mktemp "${TMPDIR:-/tmp}/mbox-linux-verification.XXXXXX")
echo "Linux verification log: $log"
./scripts/verify-linux.sh 2>&1 | tee "$log"
```

The supported Linux release architectures are `x86_64` and `aarch64`. Native
proof is architecture-specific: a successful macOS run or a build for another
target does not prove the Linux backend.

The full gate requires Linux, Rust/Cargo 1.85+, Bubblewrap 0.10+, unprivileged
user namespaces, and seccomp. It performs:

```text
shared static check
Linux static check
cargo fmt --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
locked debug build
Bubblewrap feature/user-namespace probe
Linux native A-AB contract (including fail-closed new-option checks)
```

`./scripts/verify-linux.sh --runtime-only` skips static, fmt, check, clippy, and
unit tests. It still performs a locked build, feature probe, helper build, and
native contract so stale binaries are not accepted as proof.

Exit `69` means the host lacks a required verifier prerequisite. Exit `1` means
a check or native contract failed. A successful macOS run is not Linux proof.
