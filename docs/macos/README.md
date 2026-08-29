# macOS backend

- Contract: [`CONTRACT.md`](CONTRACT.md)
- Scenarios: [`SCENARIOS.md`](SCENARIOS.md)
- Verification: [`../MACOS_VERIFICATION.md`](../MACOS_VERIFICATION.md)

```text
ExecutionPlan
  → dynamic deny-by-default Seatbelt profile
  → trusted /usr/bin/sandbox-exec
  → trusted /bin/bash positional exec -a
  → exact executable and caller-requested deny-write subtraction
  → optional parent-owned exact-domain HTTPS CONNECT proxy
  → final TIOCSTI subtraction
  → target stdio/status/signal and bounded cleanup of the initial exact-domain process group
```

The macOS-only `--no-child-processes` path is the strict variant: it skips
Bash, requires an executable Mach-O/fat Mach-O target that passes bounded
current-host structural preflight, sets `pgid == pid` in the mbox process before
direct replacement, and denies target fork/exec of another image. It is
incompatible with exact-domain `--allow-net`.

The backend depends on a macOS system interface without a public compatibility
guarantee. The repository therefore makes no forward-compatibility claim from
source inspection alone. Each supported macOS release must pass:

```sh
./scripts/verify-macos.sh
```

Release provenance uses a fixed local protocol against a clean release binary:

```sh
./scripts/verify-macos.sh --release-provenance
```

That mode cleans and rebuilds twice sequentially at the exact protocol-reserved
directory
`/Users/ax/repoGithub/mbox/target/.mbox-release-v2`, compares bytes, runs the complete native
contract A-AQ + AE, and installs only the verified artifact at
`/Users/ax/repoGithub/mbox/target/release/mbox`. The current host-specific
record is [`RELEASE-v0.2.0.sha256`](RELEASE-v0.2.0.sha256). Its complete Mach-O
digest is protocol-specific; this is not arbitrary-checkout path-independent
reproducibility evidence. The record also pins the canonical absolute
Cargo/rustc/rustfmt/clippy-driver paths and SHA-256 values, fixed linker/XCRun
and hash-tool paths and digests, canonical SDK path, and both source and
compiled release-helper digests. The verifier uses those exact binaries with a
fixed system `PATH`, clears build overrides, and rechecks their digests before
each security-critical use; nested gates do not resolve tools from ambient
`PATH`.

Every release-critical shell entrypoint starts through Darwin's exact
`/usr/bin/env -S -i` form with a small protocol-owned environment. This removes
`BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`, `GLOBIGNORE`,
`BASH_XTRACEFD`, and ambient `PATH` before Bash starts. Nested release,
verification, static-check, and contract calls use the allowlisted
`mbox_release_run_script` runner and pass required paths explicitly. Invoking
these files as `bash path/to/script` bypasses the pre-Bash boundary and is
unsupported; the scripts reject that path when the boundary marker is absent.

The final install is performed by the repo-owned Darwin helper
`scripts/macos/atomic_install.rs`, not a shell `cp` or in-place write. It holds
the canonical release directory by fd, uses `O_DIRECTORY|O_NOFOLLOW`, rejects
symlinks, unsafe owners/modes/devices, and hardlinked destinations, copies to a
unique `O_EXCL` temp inode, applies executable mode, fsyncs the file, atomically
renames only `mbox`, fsyncs the directory, and reopens the result by fd to
verify its inode and metadata. The provenance record carries the helper's
separate `release-helper-sha256`; it is not folded into the binary-affecting
source fingerprint. Same-account path replacement and a second mounted device
remain operator [UNVERIFIED] boundaries.

The strict record parser gates the protocol, mbox version, host/architecture,
Rust/Cargo versions, deterministic source fingerprint, reserved build root/path,
install path, and final SHA-256. It bounds record lines/bytes and rejects shell
metacharacters as data. Run `./scripts/macos/release-check.sh --self-test` to
prove stale and hostile record copies, altered tool paths/digests, an altered
compiled helper, and hostile `PATH` tools are rejected without modifying the
tracked record or creating a marker.

A Linux build or static policy review is not macOS native proof.

The repeatable Darwin procedure is in
[`../MACOS_VERIFICATION.md`](../MACOS_VERIFICATION.md). Its command output and
host identity are caller-owned release evidence and must be stored outside the
repository as described in [`../OPERATIONS.md`](../OPERATIONS.md). Keep that
evidence separate from this platform contract: it is a host/run record, not a
new runtime authority or a compatibility promise.
