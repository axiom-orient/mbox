# macOS verification

Run from the repository root on the supported Darwin host. This is a repeatable
native runbook, not a dated receipt. The complete script performs the macOS
static checks, locked formatting/check/clippy/tests, and then the native
contract. The contract performs its own locked binary and helper build before
executing the scenarios, including caller-owned temporary-directory validation,
executable-parent authority denial, a controlling-PTY `TIOCSTI` denial probe,
exact-executable protection inside a writable parent, and exact-network
lifecycle/resource checks:

```sh
set -o pipefail
macos_log=$(mktemp "${TMPDIR:-/tmp}/mbox-macos-verification.XXXXXX")
echo "macOS verification log: $macos_log"
./scripts/verify-macos.sh 2>&1 | tee "$macos_log"
```

To skip the static, formatting, check, clippy, and unit-test gates while still
rebuilding and running the native contract, use:

```sh
./scripts/verify-macos.sh --runtime-only
```

For release evidence, use the fixed release-provenance mode. It validates the
source-controlled record, cleans the exact protocol-reserved build directory
`/Users/ax/repoGithub/mbox/target/.mbox-release-v2`, performs two sequential
clean `--release --locked` builds at that same directory, compares bytes and SHA-256,
checks `--version`/`--help`, and runs the complete native contract against the
protocol-built binary. A pre-existing ignored `target/release/mbox` is never
treated as input or deleted; only the marker-owned reserved directory is
cleaned:

```sh
./scripts/verify-macos.sh --release-provenance
```

The current host-specific release record is maintained in
[`macos/RELEASE-v0.2.0.sha256`](macos/RELEASE-v0.2.0.sha256). It records the
exact protocol, canonical root/path, mbox version, Darwin host/architecture,
Rust/Cargo versions, the canonical absolute Cargo/rustc/rustfmt/clippy-driver
paths and SHA-256 values, the fixed linker/XCRun/hash-tool paths and digests,
canonical SDK path, reserved build root/path, install path, source fingerprint,
separate source and compiled release-helper SHA-256 values, and final binary
SHA-256. Release provenance replaces the ambient `PATH` with the fixed system
path, clears build overrides, and rechecks each recorded executable immediately
before a security-critical use; nested gates receive the same exact paths and
cannot fall back to ambient command lookup. The reserved build directory is deleted only after
canonical path, owner, device, no-symlink, and exact marker checks; a missing or
invalid marker fails closed. After all gates pass, the verified detached artifact
is installed by the audited native dirfd-relative helper at the exact AXD path
`/Users/ax/repoGithub/mbox/target/release/mbox` and rehashed. The record is
source-controlled and covered by `MANIFEST.sha256`; it is not part of the
binary, so the provenance file cannot create a circular binary digest.

The helper rejects an existing destination symlink or hardlink, unsafe modes,
wrong owner/device, and unsafe release directories. It creates no persistent
temporary file: failures unlink only their own exact temp name, while a normal
existing single-link executable is replaced by a new inode through `renameat`
after file and directory fsync. The final canonical path is checked for
symlinks, owner/device, digest, version/help, and the complete native contract
again after installation. A same-device mount or same-account rename race is
not proven by this local protocol.

This is path-specific macOS evidence, not a claim that a fresh checkout at an
arbitrary path is byte-reproducible. Darwin Mach-O linker output, including
values such as `LC_UUID` and code-signature data, can vary with output path and
host. The residual linker, SDK, kernel, and same-account filesystem mutation
limits remain host/operator risks outside this record.

The record parser is strict and data-only: every field is required exactly once,
line/field counts and sizes are bounded, shell metacharacters are rejected, and
stale protocol, host, toolchain, source-fingerprint, release-helper, or SHA-256
values fail closed.
The non-mutating record self-test proves stale SHA and source-fingerprint
records, altered recorded tool paths/digests, altered compiled-helper digests,
and hostile `PATH` tools are rejected using temporary copies without a marker
side effect:

```sh
./scripts/macos/release-check.sh --self-test
```

The macOS contract index is [`macos/README.md`](macos/README.md), with the
platform contract in [`macos/CONTRACT.md`](macos/CONTRACT.md) and the scenario
matrix in [`macos/SCENARIOS.md`](macos/SCENARIOS.md). Invocation recipes are in
[`USAGE.md`](USAGE.md), and caller-owned build, log, cleanup, and release
practice is in [`OPERATIONS.md`](OPERATIONS.md). The verifier owns the macOS
static check and native contract; it does not consume mixed-platform artifacts.

The script requires Darwin and an executable `/usr/bin/sandbox-exec`; it exits
69 when a host prerequisite is unavailable. This native gate is mandatory
because Seatbelt's command interface does not provide a public compatibility
guarantee. Normal-mode preparation also requires `/bin/bash` and checks both
system launchers for a canonical, root-owned, executable file that is not
group/other writable or a symlink. Strict `--no-child-processes` preparation
skips Bash and performs bounded current-host Mach-O/fat structural preflight
before direct replacement; structurally rejected images fail setup `125`.
The preflight does not duplicate kernel, dyld, code-signature, or complete
runtime-loader validation, so later loader/runtime failures remain native
target results.

The release-critical shell boundary is part of this gate: each executable
entrypoint starts with Darwin `/usr/bin/env -S -i` and a fixed minimal
environment. Nested script calls use the release runner's explicit allowlist;
they do not call ambient `bash` or inherit startup/build override variables.
`bash script` is unsupported and fails closed at the boundary-marker check.

The complete run succeeds only when all of these checks pass. Interactive
exact-mode PTY foreground handoff/restoration remains `[UNVERIFIED]` and is
not represented as a release proof:

```text
seatbelt functional probe: PASS
macos static-check: PASS
cargo fmt --check: exit 0
cargo check --all-targets --locked: exit 0
cargo clippy --all-targets --locked -- -D warnings: exit 0
cargo test --all-targets --locked: exit 0
locked binary and helper build inside the contract: exit 0
contract A-AQ + AE: PASS (Darwin)
two sequential clean release builds at one reserved path: identical bytes and SHA-256
complete contract against clean release binary: PASS
stale SHA/source-fingerprint and hostile-field record self-tests: rejected without side effects
```

## Evidence interpretation

The complete case list and expected observations are maintained once in
[`macos/SCENARIOS.md`](macos/SCENARIOS.md). Use that matrix when reviewing a
failure instead of copying a dated scenario receipt into this runbook. The
AE/AG/AI/AJ cases are the lifecycle evidence: they cover Darwin PID/start
identity, bounded TERM/KILL observation, active-tunnel cleanup, same-group
descendants, and the deliberate `setsid(2)`/double-fork escape. Direct-exec
paths do not supervise target processes. Keep any run-specific log outside the
repository when release evidence is required.

The optional developer-tool recipe in
[`macos/CONTRACT.md`](macos/CONTRACT.md#optional-developer-tool-capability-recipe)
is intentionally outside this gate. It demonstrates explicit Xcode/tool-prefix
reads, `/private/var/select`, Darwin user-temp write access, isolated HOME, and
caller-owned 0700 `--tmp`; Xcode and Homebrew are not required for core
verification.

A successful build or a Linux run does not prove this macOS gate. Rerun it after
source, policy, launcher, or supported-macOS changes. A missing prerequisite is
exit `69`; a check or native-contract failure is exit `1`. Do not replace either
with a weaker launcher or report an unrun gate as evidence.
