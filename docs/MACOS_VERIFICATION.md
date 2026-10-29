# macOS verification

Use the pinned Rustup toolchain, including its `llvm-tools` component. Release
builds use these tools for symbol stripping; a missing LLVM library is a
toolchain failure to resolve before recording a release.

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

The host-specific release record is maintained in
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
binary, so the provenance file cannot create a circular binary digest. The
record describes its recorded release; the record gate must verify that its
source fingerprint and toolchain still match before it can be used for a run.

The verifier checks an existing record; it has no record-generation command.
When source, toolchain, or fixed tool digests change, retain the previous
record and measure a candidate from actual builds at the same reserved path.
Observe all tool, source, helper, and binary digests rather than copying expected
success values. Update the manifest with the candidate, then run the original
full provenance gate. Publish the record only after that gate succeeds. A
candidate's hash alone is not release evidence.

The helper rejects an existing destination symlink or hardlink, unsafe modes,
wrong owner/device, and unsafe release directories. Before replacement, failures
attempt to unlink only their own exact temporary name; an unlink failure or
forced termination may leave it behind. A normal existing single-link
executable is replaced by a new inode through `renameat` after the file fsync,
followed by a directory fsync. If that fsync or subsequent verification fails,
the destination may already have been replaced. The final canonical path is
checked for symlinks, owner/device, digest, version/help, and the complete
native contract again after installation. A same-device mount or same-account
rename race is not proven by this local protocol.

This is path-specific macOS evidence, not a claim that a fresh checkout at an
arbitrary path is byte-reproducible. If no second filesystem is mounted, the
installer self-test reports cross-device behavior as `NOT_PROVEN`; the rest of
the gate does not turn that into a cross-device claim. Darwin Mach-O linker
output, including values such as `LC_UUID` and code-signature data, can vary with output path and
host. The residual linker, SDK, kernel, and same-account filesystem mutation
limits remain host/operator risks outside this record.

The record parser is strict and data-only: every field is required exactly once,
line/field counts and sizes are bounded, shell metacharacters are rejected, and
stale protocol, host, toolchain, source-fingerprint, release-helper, or SHA-256
values fail closed.
The record self-test preserves the tracked record and proves stale SHA and
source-fingerprint records, altered recorded tool paths/digests, altered
compiled-helper digests, and hostile `PATH` tools are rejected using temporary
copies without a marker side effect. It compiles a helper under `target`:

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

The ordinary gate prints a separate `seatbelt functional probe: PASS` before
its checks. Release-provenance mode delegates directly to the release protocol
and exercises Seatbelt through the complete contract against its built artifact.
The complete release run requires the following checks. The interactive PTY
check below is optional and is not executed by the core release gate:

```text
two sequential clean release builds at one reserved path: identical bytes and SHA-256
static-check: PASS
macos static-check: PASS
cargo fmt --check: exit 0
cargo check --all-targets --locked: exit 0
cargo clippy --all-targets --locked -- -D warnings: exit 0
cargo test --all-targets --locked: exit 0
helper build inside the contract: exit 0; the release binary is supplied with BUILD_MBOX=0
complete contract against clean release binary: PASS
atomic install, installed digest/version/help, and complete installed contract: PASS
stale SHA/source-fingerprint and hostile-field record self-tests: rejected without side effects
```

## Optional interactive PTY check

After the native gate builds mbox and its macOS probe, use Python 3.9+ to exercise
an actual controlling terminal:

```sh
python3 tests/macos/interactive_pty.py
```

To select the artifact installed by the release protocol and an external
parent directory for evidence:

```sh
python3 tests/macos/interactive_pty.py \
  --mbox "$PWD/target/release/mbox" \
  --evidence-dir "${TMPDIR:-/tmp}"
```

This standalone check uses only Python's standard library. It is not a Python
dependency of mbox or the core native gate. The defaults run five normal-input
cases and three terminal Ctrl-C cases. Each case checks the target PID/PGID and
foreground group, exact input and status `37` or signal status `130`, restoration
of the original foreground group, and successful subsequent caller input. It
also requires the driver to be reaped and no captured PID/start identity to
survive. Cleanup signals only a freshly matching PID/start identity.

The check never uses the caller's terminal. It writes binary/probe SHA-256,
host identity, transcripts, and results to a new `mbox-pty-*` directory outside
the repository and prints that path. Retain it with the caller's run log.
A pass proves these interactions for the selected binary and host; it does not
prove every job-control timing or cleanup of descendants that escaped the
initial process group.

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
