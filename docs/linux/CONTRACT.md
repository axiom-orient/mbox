# Linux execution contract

## Boundary

`platform::linux::prepare` accepts the immutable shared plan and prepares a
trusted Bubblewrap `0.10.0+` command. The target never runs when launcher trust,
version, mount pinning, memfd creation, or command construction fails.
Linux release support is intentionally limited to `x86_64` and `aarch64`; other
architectures fail at compile time. Native proof requires the Linux verifier on
the architecture under test.

## Filesystem

The sandbox begins with an empty tmpfs root. Common runtime code is mounted
read-only from selected `/usr/bin`, library, share, and include roots plus a
small set of identity and loader files. `/usr/local` is not ambient. Resolver
and trust-store files are ambient only with `--network`; unusual host or
user-managed toolchains require explicit `--read`.

Every source is pinned with an `O_PATH|O_NOFOLLOW` descriptor during
preparation. Bubblewrap receives `--ro-bind-fd` or `--bind-fd`; it does not
reopen the user pathname. This requires Bubblewrap `0.10.0+`.

Readable parents are mounted before writable descendants. The exact executable
is reasserted read-only afterward, which protects executable identity without
hiding a writable child. The synthetic root is remounted read-only
non-recursively, so writable submounts remain writable.
`/tmp` and `/dev/shm` are anonymous tmpfs mounts and disappear with the process
tree. They are sandbox-private scratch, not projections of host `/tmp`; host
write-authority tests therefore use a fixture outside `/tmp`.

## Process and network

The backend creates user, PID, IPC, and UTS namespaces. Network is unshared by
default. All capabilities are dropped and `--disable-userns` prevents creation of
further user namespaces.
A PID-namespace reaper and `--die-with-parent` own descendant shutdown.

The seccomp baseline denies cross-process memory access, io_uring, and terminal
input injection. With network denied it additionally blocks all `socket()`
creation and endpoint/message syscalls. Anonymous `AF_UNIX socketpair()` remains
for local runtime IPC; pathname Unix sockets are unavailable. Because
`sendmsg` and `recvmsg` are denied, `SCM_RIGHTS` descriptor passing is also
unavailable while network is denied.

`--new-session` is not used. This preserves foreground process-group behavior,
while argument-aware seccomp rules block `TIOCSTI` and `TIOCLINUX`.

The shared CLI accepts `--allow-net DOMAIN` and `--deny-write PATH` so callers
can use one explicit contract, but Linux native implementation is not claimed
yet: either option fails setup with status `125` before Bubblewrap or the target
starts. `--no-child-processes` is likewise macOS-only and fails setup with
status `125` before Bubblewrap or the target starts. A future Linux
implementation requires its own native bypass and subtraction proof; it must
not silently ignore any of these options.

## Trust requirements

The launcher must be `/usr/bin/bwrap` or `/bin/bwrap`, resolve to a regular
root-owned executable, have no setuid/setgid bits, and not be writable by group
or others. Its canonical parent chain must have the same ownership/write
property. Version output must parse as `0.10.0` or newer.

The host must support user namespaces and seccomp filters. Absence is a blocked
environment, never permission to run directly. Bubblewrap `--disable-userns`
limits nested namespaces through `user.max_user_namespaces`; a nested
`unshare(CLONE_NEWUSER)` can therefore fail with either `EPERM` or `ENOSPC`,
and both mean the namespace was blocked.

Ubuntu 24.04+ enables AppArmor restrictions on unprivileged user namespaces by
default. A host policy must explicitly permit Bubblewrap's user-namespace setup
(for example with an administrator-managed AppArmor policy). mbox does not
disable this host protection or fall back to a weaker sandbox.

## Residual limits

- Authorized writable roots retain normal host filesystem semantics.
- User-managed `/usr/local`, home-directory, and custom toolchain data require explicit `--read`.
- Resource exhaustion is outside mbox; the caller should apply cgroup/rlimit or
  an upper runner when required.
- A socket supplied as stdin/stdout/stderr remains an explicit standard-I/O
  capability; network denial does not reinterpret standard I/O.
