# mbox operations runbook

This runbook is for the caller or integrator that builds, invokes, observes,
and upgrades `mbox`. It assumes the public behavior in
[`CONTRACT.md`](CONTRACT.md) and the invocation rules in
[`USAGE.md`](USAGE.md). `mbox` is not a daemon: it has no service lifecycle,
persistent policy store, telemetry, or built-in log sink. The upper runner owns
the run record and resource controls.

## 1. Preflight and release identity

Run from the mbox repository root and record the source, lockfile, compiler,
host, and native launcher:

```sh
cargo --version
rustc --version
cargo build --release --locked
target/release/mbox --version
```

Record the release binary's SHA-256 in caller deployment metadata. The binary
does not implement digest pinning itself:

```sh
# macOS
shasum -a 256 target/release/mbox

# Linux
sha256sum target/release/mbox
```

Use the digest as a caller-side identity check before promotion. A successful
Cargo build does not prove either native backend; run the matching host gate.

## 2. Host and native preflight

Choose the gate from the actual host, not the desired deployment target:

```sh
./scripts/verify.sh --runtime-only
```

For release evidence, run the full gate on the native host:

```sh
# Darwin only
./scripts/verify-macos.sh

# Linux only
./scripts/verify-linux.sh
```

The macOS gate requires a functional trusted `/usr/bin/sandbox-exec` and
`/bin/bash`. The Linux gate requires a trusted root-owned non-setuid Bubblewrap
0.10+ launcher, supported `x86_64`/`aarch64` architecture, user namespaces,
and seccomp. A gate on the wrong OS exits `69`; it is an environment block, not
permission to use a weaker launcher. Never report Linux proof from Darwin.

Keep command output and host/toolchain identity with the release record. The
repeatable procedures are in [`MACOS_VERIFICATION.md`](MACOS_VERIFICATION.md)
and [`LINUX_VERIFICATION.md`](LINUX_VERIFICATION.md).

## 3. Review every run's authority

Before launching a target, record:

1. The exact executable, `argv`, and cwd.
2. Existing read roots and writable roots, including the cwd's implicit read
   authority.
3. On macOS, any `.git` or other control path to subtract with `--deny-write`.
   Do not pass this option on Linux; it exits `125`.
4. Whether default network deny is sufficient, macOS exact-domain access is
   sufficient, or full `--network` is truly required.
5. The minimal environment; avoid `--inherit-env` when explicit variables work.
6. Whether macOS needs a caller-owned 0700 `--tmp`, and who removes it.
7. Which timeout, memory, process, output, and disk limits the upper runner
   will enforce.

Reject a request that cannot answer these questions. `mbox` does not infer a
profile or silently broaden authority for convenience.

## 4. Execute and capture evidence

The target's stdin/stdout/stderr and status are direct. If a caller needs a log,
capture it outside mbox and preserve the target status explicitly. The example
is a Bash wrapper because `PIPESTATUS` is Bash-specific; it exits with the
target's status rather than `tee`'s status:

```bash
set -o pipefail
run_log="/path/to/caller-run.log"
"$MBOX" --cwd "$WORK" --read "$WORK/input" -- \
  /bin/cat "$WORK/input" 2>&1 | tee "$run_log"
run_status=${PIPESTATUS[0]}
exit "$run_status"
```

Do not place credentials, full request bodies, or untrusted output in a shared
long-lived log without a retention policy. mbox emits no persistent URL,
header, credential, body, or policy logs and retains no execution state.

Apply upper-runner controls around the invocation: wall-clock cancellation,
CPU/memory/process limits, output quotas, disk quotas, and retry/idempotency
policy. A target that fails after an authorized partial write can leave partial
state; retries must be safe for that target.

## 5. Temporary and process cleanup

On macOS, create a dedicated 0700 `--tmp` directory before the run and remove
that exact caller-owned directory after checking the target result. mbox never
creates or deletes it. On Linux, `/tmp` and `/dev/shm` are anonymous namespace
mounts and disappear with the process tree; host-write checks should use an
explicit host root rather than assuming sandbox `/tmp` is persistent.

Direct-exec paths do not supervise a target. macOS exact-domain mode has a
narrow supervisor only to own the proxy, tunnel, and target's initial process
group; it performs bounded TERM, KILL, observation, and reap work. A target that
calls `setsid(2)` and double-forks can escape that process group. This is an
executable negative boundary (scenario AJ), not cleanup success. Do not run
untrusted descendant trees in exact-domain mode when no-survivor cleanup is a
requirement; use a separately approved upper-level lifecycle primitive.

After a run, check only expected output paths and the exact caller temp/log
paths. Do not use broad process cleanup (`killall`, `pkill`, or a pattern kill)
as a substitute for identity-aware ownership. If cancellation leaves a possible
escaped descendant, retain its specific PID/start-identity evidence and
escalate it instead of claiming sandbox cleanup.

## 6. Verification evidence

The shared static check is:

```sh
./scripts/static-check.sh
```

Full native gates additionally run locked formatting/check/clippy/tests,
backend prerequisites, and the platform contract. `--runtime-only` skips
static, formatting, lint, and unit-test stages but still rebuilds and runs the
native contract.

| Observation | Meaning |
|---|---|
| static check passes | source/manifest/document surface checks passed |
| macOS gate passes on Darwin | Seatbelt, proxy, lifecycle, and macOS contract passed on that host |
| Linux gate passes on Linux | Bubblewrap, namespaces, seccomp, and Linux contract passed on that host/architecture |
| gate exits `69` | required host tool or native prerequisite is unavailable |
| gate exits `1` | a check or native contract failed; investigate before promotion |
| gate run on the other OS | not native proof |

The macOS exact-domain scenarios retain the initial-TLS-SNI and
`setsid`/double-fork limits. Do not turn a scenario failure or an unverified
interactive PTY handoff into a release claim.

## 7. Failure triage

Classify the first observed failure before changing authority:

| Symptom | Likely class | Action |
|---|---|---|
| exit `2` before target output | CLI contract | inspect `--` placement, option spelling, duplicate single-use options, and values |
| exit `125` before target output | plan or launcher setup | inspect paths, env ownership, hardlinks, trusted launchers, platform-only options, and exact-domain syntax |
| target cannot read/write an expected path | authority selection | verify canonical path, existing `--write` root, and target cwd; do not add broad roots blindly |
| exact-domain request cannot connect | macOS proxy/SNI boundary or target proxy use | confirm exact DNS name, HTTPS port 443, initial SNI, and target proxy support; do not switch to full network without review |
| gate exits `69` | environment | install/approve the required prerequisite or mark the host unverified; do not bypass the gate |
| gate exits `1` | regression or fixture failure | preserve the log, source/build identity, and first failing scenario; reproduce on the same native host |
| output is partial after failure | target write semantics | inspect authorized artifacts and use target-specific recovery/idempotency; mbox has no rollback |
| descendant remains after exact-mode cancellation | known lifecycle boundary or regression | identify PID/start tuple, compare with scenario AJ, and escalate; do not claim cleanup |

## 8. Upgrade and rollback

For a new source revision, compiler, Bubblewrap, `/usr/bin/sandbox-exec`, or
supported OS release:

1. Build with `cargo build --release --locked` and record version plus digest.
2. Run the full native gate on every deployment platform and architecture.
3. Run a minimal real command for every authority mode the caller uses: offline
   read, selected write, and the approved network mode.
4. Promote only after evidence and authority review are stored with the release
   record.
5. If a gate or smoke test fails, keep the last known-good binary and digest in
   service, investigate the candidate separately, and rerun the same evidence.

Rollback means restoring a previously verified binary selected by its recorded
caller-side digest. It is not an mbox runtime fallback and must not silently
broaden network or filesystem authority.

## 9. Incident boundary

Preserve the exact request, binary digest, host/kernel/launcher versions, gate
log, target status, expected/observed artifacts, and identity-aware cleanup
record. Rotate or remove sensitive logs according to the caller's policy. Do
not delete source, fixtures, or evidence while diagnosing. A future change
that needs stronger resource limits, inode identity, process containment, or
forward-compatible macOS enforcement requires a new contract and native proof.
