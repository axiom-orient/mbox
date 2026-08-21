# mbox execution contract

This is the shared public invariant set. Use [`USAGE.md`](USAGE.md) for
task-oriented invocation and [`OPERATIONS.md`](OPERATIONS.md) for caller-owned
build, cleanup, resource, and release procedures. Platform-specific details are
canonical in [`macos/CONTRACT.md`](macos/CONTRACT.md) and
[`linux/CONTRACT.md`](linux/CONTRACT.md).

## Identity

`mbox` converts one explicit CLI request into an immutable `ExecutionPlan`,
prepares the native sandbox, closes ambient file descriptors, and replaces
itself with the native launcher. Direct-exec requests are not supervised;
macOS exact-domain requests deliberately supervise only to own the proxy and
cleanup of the target's initial process group.

```text
argv + selected environment + filesystem metadata
  → cli::parse
  → ExecutionPlan::build
  → platform::prepare
  → close inherited FD capabilities
  → native launcher exec (or exact-domain target-group supervisor)
  → target stdio/status/signal
```

## Canonical state

`ExecutionPlan` is the only application state. It owns the canonical executable,
original `argv0`, arguments, cwd, minimized read/write roots, optional macOS
temporary directory, environment, and network decision. It is immutable after
construction.

There is no persistent state, profile, daemon, retry loop, background task,
transaction, or fallback backend.

## Filesystem authority

- cwd, command, `--read`, `--write`, and `--tmp` inputs must exist.
- cwd is read-only unless covered by an explicit write root.
- File roots are exact; directory roots include descendants.
- A containing write root supersedes a read root.
- `/` cannot be writable.
- The target executable is readable, but its parent directory is not an
  implicit user authority. Even when an explicit write root contains it, the
  exact canonical executable is reasserted read-only.
- macOS `--deny-write PATH` is a caller-owned final subtraction. Existing
files and directories are canonicalized; a nonexistent leaf is resolved
against its canonical existing parent and receives recursive subpath
subtraction so a writable parent cannot create, write, remove, rename, or
replace the protected path. Symlink deny paths are rejected so the caller must
name the actual protected object. Linux rejects this new option with setup status
  `125` until a native subtraction proof exists.

Linux opens every mount source component-by-component with `O_PATH` and
`O_NOFOLLOW` during preparation, retains the resulting descriptor, and uses
Bubblewrap `--[ro-]bind-fd`. Replacing a pathname after the descriptor is open
does not change the mounted inode. The caller and host remain trusted before
that prepare-time open.

macOS Seatbelt accepts path rules rather than mount descriptors. Inputs are
canonicalized and the generated policy grants only ancestor metadata plus exact
file/subpath authority. Host path replacement after the final check remains a
platform limitation; mbox does not claim descriptor or inode identity on macOS.
Existing hardlinked protected files (recursively for protected directories) and
the selected executable are rejected before launch, and the sandbox denies
target hardlink creation. A trusted caller can still introduce an alias after
planning; that race is outside the path-based contract.

## Environment authority

The default environment is limited to command lookup, user/shell/terminal
identity, locale, and certificate hints. `--env`, `--set-env`, and
`--inherit-env` are explicit expansions.

The following remain mbox-owned or forbidden:

```text
PWD OLDPWD TMPDIR
LD_* DYLD_*
BASH_ENV ENV SHELLOPTS BASHOPTS CDPATH GLOBIGNORE
```

`PWD` is canonical cwd. Linux sets `TMPDIR=/tmp` inside an anonymous tmpfs.
macOS sets `TMPDIR` only when the caller supplies a valid `--tmp` directory.

## Network authority

Default is deny.

- macOS emits no network allowance.
- Linux creates a new network namespace and applies a seccomp network filter.
  It denies `socket()` and endpoint/message syscalls, while retaining anonymous
  `AF_UNIX socketpair()` for in-process IPC. `sendmsg`/`recvmsg` are denied
  in this mode, so descriptor passing is intentionally unavailable.
- `--network` keeps the host network namespace and removes only the
  network-specific seccomp rules. Baseline process and TTY protections remain.

`--network` is the explicit full-network mode and cannot be combined with
`--allow-net`. On macOS, repeatable `--allow-net DOMAIN` values are normalized
to lowercase exact ASCII DNS names; trailing dots, wildcards, URLs, ports, and
IP literals are rejected. The target may only issue HTTPS `CONNECT` requests
to port `443`. mbox owns an ephemeral loopback HTTP CONNECT proxy and overrides
both proxy-variable cases while removing `ALL_PROXY`/`NO_PROXY` cases. Seatbelt
allows target outbound traffic only to that one loopback port, so environment
tampering, direct IP sockets, DNS bypass, other loopback ports, inbound, and
bind attempts remain denied. The proxy resolves once, rejects any non-public
answer (including private, local, reserved, test, and IPv4-mapped IPv6 ranges),
then dials the validated `SocketAddr` without a second lookup. It retains no
URL, header, credential, body, or policy state. Before forwarding on macOS,
the proxy requires the first TLS ClientHello SNI to equal the CONNECT authority;
plaintext, malformed or missing SNI, duplicate/multiple names, ECH, oversize,
and deadline violations fail closed. This is an initial-SNI boundary only; it
does not parse a later TLS 1.3 HRR ClientHello or encrypted application-layer
hostname. Linux rejects `--allow-net`
with setup status `125` until its own native proof exists.

## Native backends

### macOS

`/usr/bin/sandbox-exec` loads a deny-by-default Seatbelt profile. `/bin/bash`
performs one positional `exec -a` so the original command spelling remains
`argv0` without interpolating target arguments into shell source.

`--tmp` is caller-owned: mbox neither creates nor deletes it. This preserves
direct exec semantics without pretending that Rust cleanup can run afterward.
Exact-domain macOS mode is the deliberate exception: mbox supervises the
target process group so it can own the proxy and close active tunnels on normal
exit, cancellation, signal, or proxy failure. Standard streams remain direct,
normal target exit codes are preserved, and signal exits map to `128 + signal`.
The leader remains waitable through Darwin `waitid(WNOWAIT)` while its process
group is cleaned, preventing a stale numeric PGID from being reused for a
different process. The exact proxy owns both `127.0.0.1:EPHEMERAL` and
`[::1]:EPHEMERAL` with the same bounded CONNECT handler. It caps connection
workers, reaps finished workers during runtime, and bounds DNS helper threads;
a resolver helper that the OS keeps stuck is left detached until process
teardown rather than being falsely reported as joined. Darwin process groups do
not follow a target that calls `setsid(2)` and double-forks; scenario AJ records
that escaped descendant, so exact mode is not a no-survivor guarantee for such
targets. Interactive exact-mode PTY handoff/restoration is `[UNVERIFIED]` by
the current macOS gate.
TERM cleanup has a bounded grace period followed by SIGKILL and a second
bounded observation period; if the leader still cannot be observed as exited,
supervision fails instead of claiming cleanup succeeded.
The Seatbelt compiler appends a final `file-ioctl` deny for Darwin `TIOCSTI`
while retaining ordinary terminal ioctls and direct foreground signal behavior.

### Linux

Bubblewrap must be version `0.10.0` or newer. mbox uses:

Linux release support is limited to `x86_64` and `aarch64`; other Linux
architectures fail at compile time. Native Linux proof is valid only on a
Linux host for the architecture under test and cannot be substituted by a
macOS build or a weaker launcher.

- empty tmpfs root;
- user, PID, IPC, UTS, and default-deny network namespaces;
- all capabilities dropped;
- pinned FD read/write mounts;
- private `/proc`, `/dev`, `/tmp`, and `/dev/shm`;
- a sealed seccomp memfd;
- `--die-with-parent` and a PID-namespace reaper.

`--new-session` is intentionally not used so foreground terminal behavior is
preserved. The seccomp filter therefore denies `ioctl(TIOCSTI)` and
`ioctl(TIOCLINUX)` with `EPERM`.

The baseline seccomp filter also denies:

```text
ptrace
process_vm_readv
process_vm_writev
io_uring_setup
io_uring_enter
io_uring_register
```

## I/O, lifecycle, and failure

- File descriptors `0`, `1`, and `2` are inherited.
- Other inherited descriptors are closed before launcher exec, except Linux
  setup descriptors consumed by Bubblewrap.
- Rust does not buffer target output. Direct-exec paths do not wait for the
  target; exact-domain macOS mode waits only to own its proxy/tunnel lifecycle
  and returns the target's status.
- Target exit/signal results are returned by the native launcher.
- CLI errors exit `2`.
- Validation/preparation errors before launcher exec exit `125`.
- Launcher failures after replacement retain the launcher-native result.
- No error enables an unsandboxed or weaker execution path.

On Linux, cancelling the outer Bubblewrap process must release a host-visible
lock held by a sandbox descendant; tests do not treat namespace-local PIDs as
host PIDs.

## Artifacts and recovery

| Artifact | Owner | Lifetime |
|---|---|---|
| explicit target writes | target/caller | persistent by target semantics |
| Linux `/tmp`, `/dev/shm` | kernel namespace | sandbox process lifetime |
| Linux mount/seccomp FDs | mbox/Bubblewrap | setup only |
| macOS `--tmp` contents | caller/target | caller-controlled |
| mbox logs/state | none | none |

mbox provides no rollback. A target that partially writes an authorized path
before failing may leave partial data. Atomicity and idempotency belong to the
target or upper executor.

## Non-goals

- resource quotas or wall-clock timeout;
- content filtering inside authorized paths;
- package/container image management;
- profile or policy persistence;
- remote execution;
- proof that an unsupported future OS preserves private sandbox interfaces.

## Verification

- Shared static source checks: `scripts/static-check.sh`
- macOS gate: `scripts/verify-macos.sh`
- Linux gate: `scripts/verify-linux.sh`
- User recipes: `docs/USAGE.md`
- Operations runbook: `docs/OPERATIONS.md`
- Verification procedures: `docs/MACOS_VERIFICATION.md` and
  `docs/LINUX_VERIFICATION.md`
- Platform scenario indexes: `docs/macos/SCENARIOS.md` and
  `docs/linux/SCENARIOS.md`
