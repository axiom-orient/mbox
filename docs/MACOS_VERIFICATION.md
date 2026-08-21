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

The macOS contract index is [`macos/README.md`](macos/README.md), with the
platform contract in [`macos/CONTRACT.md`](macos/CONTRACT.md) and the scenario
matrix in [`macos/SCENARIOS.md`](macos/SCENARIOS.md). Invocation recipes are in
[`USAGE.md`](USAGE.md), and caller-owned build, log, cleanup, and release
practice is in [`OPERATIONS.md`](OPERATIONS.md). The verifier owns the macOS
static check and native contract; it does not consume mixed-platform artifacts.

The script requires Darwin and an executable `/usr/bin/sandbox-exec`; it exits
69 when a host prerequisite is unavailable. This native gate is mandatory
because Seatbelt's command interface does not provide a public compatibility
guarantee. During preparation, `mbox` also requires `/bin/bash` and checks both
system launchers for a canonical, root-owned, executable file that is not
group/other writable or a symlink.

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
contract A-AJ + AE: PASS (Darwin)
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
