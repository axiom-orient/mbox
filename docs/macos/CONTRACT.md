# macOS execution contract

This document is the macOS-specific companion to the shared execution
contract. The implementation and policies are the authority when this text
disagrees with code.

## Backend choice

The current backend is intentionally Seatbelt through
`/usr/bin/sandbox-exec`. It is the smallest practical way to apply a dynamic
per-command filesystem/network policy while preserving native macOS binaries,
stdio, argv, and exit behavior. It is not a public API with a compatibility
guarantee, so mbox treats its presence and native contract as a release gate
and fails closed when it is unavailable.

App Sandbox is entitlement/signing based and inherited by child processes; it
does not provide this CLI's dynamic authority contract. Endpoint Security and
Virtualization.framework require a privileged extension/supervisor or a VM and
would change mbox into a substantially larger product. They remain alternatives
only if the product identity changes from a minimal native command sandbox.

## Native boundary

On macOS, `platform::prepare` validates `/usr/bin/sandbox-exec` and `/bin/bash`.
Both must be canonical regular files that are root-owned, executable,
free of setuid/setgid bits, and not writable by group or others. Every
canonical parent directory must also be root-owned and not writable by group
or others. There is no unsandboxed fallback. The prepared command invokes:

```text
/usr/bin/sandbox-exec -p <compiled Seatbelt policy> --
  /bin/bash --noprofile --norc -c 'exec -a "$1" "$2" "${@:3}"'
```

`--no-child-processes` is a separate strict launch contract. It validates
`/usr/bin/sandbox-exec` as above, then validates the selected target with
bounded positioned reads. The preflight checks the current-host CPU type and
native byte order, thin/fat/fat64 headers and slice table bounds/non-overlap.
Fat/fat64 headers and architecture tables are accepted only in their
big-endian on-disk form (`CA FE BA BE`/`CA FE BA BF`); the CIGAM byte
sequences are host-read swap constants and fail setup. All supported macOS
host architectures are 64-bit, so Thin32 images fail setup even when their
header CPU type is the host CPU. The remaining checks cover
`MH_EXECUTE`, bounded `ncmds`/`sizeofcmds`, 4-byte (32-bit) or 8-byte
(64-bit) load-command alignment and progression, and a complete `LC_MAIN` or
host `LC_UNIXTHREAD` entry command. Shebang files, interpreter shims,
nonregular files, unknown magic, and truncated or malformed data at these
checked boundaries—including fat files without a host executable slice—fail
setup with status `125`. `/bin/bash` is not consulted or
launched. The prepared command invokes:

```text
/usr/bin/sandbox-exec -p <compiled strict Seatbelt policy> -DEXECUTABLE=<canonical target> --
  <canonical target> [ARG...]
```

The canonical target path is `argv[0]`; caller spelling is intentionally not
preserved. The strict policy ends with `deny process-fork`, `deny
process-exec`, and an exact-target `allow process-exec`. Thus fork/vfork,
`posix_spawn`, background child creation, and exec of another image fail. The
exact target image may self-reexec. Before direct replacement mbox observes or
establishes `pgid == pid` in the same process. The target is consequently a
process-group leader and direct `setsid(2)` fails; Seatbelt is not claimed to
provide an independent setsid rule. This same-process group identity is the
outer custody proof, and setup fails if it cannot be established.

Strict mode rejects `--allow-net` because the exact-domain proxy requires a
separate supervisor; `--network` has no proxy and remains compatible. The mode
does not add inode/path pinning and does not protect against same-account/root
host mutation or post-plan path replacement.

The preflight proves only these bounded structural invariants; it does not
duplicate the kernel, dyld, code-signature, or complete runtime-loader checks.
An image that passes structure can still fail after replacement, in which case
the later loader/runtime result may be returned as the native target status.

In normal mode, the original command spelling is passed as `argv0`; the
canonical executable path is passed as the executable. `PreparedCommand::exec` closes inherited file
descriptors other than standard input/output/error before the native `exec`.
Exact-domain mode is the explicit supervised path: mbox owns ephemeral
listeners on both `127.0.0.1` and `::1` at one port and the target's initial
process group, while target standard streams stay direct. A target that calls
`setsid` and double-forks can leave that process group; scenario AJ records this
public Darwin lifecycle boundary, so exact mode does not claim no-survivor
cleanup for escaped descendants.
TERM cleanup has a bounded grace period followed by SIGKILL and a second
bounded observation period; if the leader still cannot be observed as exited,
supervision fails instead of claiming cleanup succeeded.

## Filesystem authority

The base Seatbelt policy is deny-by-default. The platform policy grants only
the macOS runtime paths required for launcher startup and standard system
operation. It does not grant ambient user trees such as `/Applications`,
`/opt/homebrew`, or `/usr/local`.

The execution plan supplies dynamic authorities:

- file reads use literal rules;
- directory reads use subpath rules;
- file and directory writes use the corresponding write rules;
- every dynamic root also receives only `file-read-metadata` and
  `file-test-existence` access through `path-ancestors`, so canonicalization
  can inspect its parent chain without reading ancestor file data;
- the selected cwd, exact executable, and explicit authorities are
  canonicalized by the shared plan builder; the executable's parent directory
  is not an implicit read authority;
- `/` cannot be writable;
- after all broad write grants, the exact canonical executable receives a
  final `file-write*` deny while retaining read and executable-map access.
- `--deny-write PATH` is appended after every write grant and executable rule.
  Existing regular files use an exact literal subtraction; existing
  directories and nonexistent leaves use recursive subpath subtraction.
  Symlink deny paths are rejected so the caller must name the actual protected
  object. This blocks create,
  write, remove, rename, and replacement beneath or at the protected path
  while sibling writes remain allowed. Existing protected regular files are
  rejected when hardlinked (recursively for protected directories), as is the
  selected executable. Seatbelt remains path-based: a trusted caller must not
  introduce a new inode alias after planning; mbox does not claim inode pinning
  across that race. `file-link` is denied in the sandbox so a target cannot
  create such an alias itself.

An explicit write root is the only way for the target to modify host data. A
write authority can supersede a contained read authority, as defined by the
shared plan, except for the exact executable subtraction above.

## Temporary storage and environment

`--tmp PATH` is optional. When supplied, `PATH` must resolve to an existing
directory owned by the effective invoking UID with exactly mode bits `0700`
(no sticky, setgid, setuid, or other special bits). The
canonical directory is added as a writable policy root and exported as
`TMPDIR`; `mbox` never creates, chmods, or deletes it. When omitted, `TMPDIR`
is absent and the target receives no temporary write authority. The caller
owns lifecycle and cleanup of the supplied directory.

The environment is cleared before the launcher command is built. The shared
plan supplies the minimal/default environment and rejects explicit launcher-
sensitive values. `PWD` and `TMPDIR` remain mbox-owned. The target inherits
stdin, stdout, stderr, exit status, and signal behavior directly.

## Optional developer-tool capability recipe

Xcode, `xcrun`, and similar tools are not part of the core gate and are not
ambient policy. A caller that intentionally uses them must provide only the
paths needed by that invocation. The following example uses an isolated HOME,
an existing caller-owned 0700 `--tmp`, explicit Xcode contents and tool prefix,
the `/private/var/select` resolver path, and explicit write access to Darwin's
native user temporary directory:

```sh
CALLER_TMP=$(mktemp -d "${TMPDIR:-/tmp}/mbox-caller.XXXXXX")
chmod 700 "$CALLER_TMP"
ISOLATED_HOME=$(mktemp -d "${TMPDIR:-/tmp}/mbox-home.XXXXXX")
chmod 700 "$ISOLATED_HOME"
XCODE_CONTENTS=/Applications/Xcode.app/Contents
TOOL_PREFIX="$XCODE_CONTENTS/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin"
DARWIN_USER_TEMP=$(getconf DARWIN_USER_TEMP_DIR)

mbox --cwd "$WORK" \
  --read /private/var/select \
  --read "$XCODE_CONTENTS" \
  --read "$TOOL_PREFIX" \
  --write "$DARWIN_USER_TEMP" \
  --write "$ISOLATED_HOME" \
  --tmp "$CALLER_TMP" \
  --set-env "HOME=$ISOLATED_HOME" \
  -- /usr/bin/xcrun --find clang
```

`--tmp` controls only the supplied caller directory. It does not redirect
Darwin native cache APIs; those APIs require an explicit write root such as
`getconf DARWIN_USER_TEMP_DIR`. Adjust the Xcode contents and tool prefix to
the installed toolchain, and add explicit user configuration reads when the
tool requires them.

## Terminal boundary

Standard streams and an interactive terminal remain direct native I/O. The
base policy therefore permits normal tty operations, but the final generated
rule subtracts Darwin `TIOCSTI` (`#x80017472`). A sandboxed process may query and
operate its terminal normally but may not push bytes into the host shell's
input queue. The native contract creates its own controlling pseudo-terminal
and requires the injection attempt to return `EPERM`.

This is the smallest mitigation that preserves direct stdio, foreground
process-group signals, and original exit behavior on direct-exec paths. Exact
network mode uses a narrow process-group supervisor only to own its proxy and
tunnel cleanup. Its tty handoff path blocks `SIGTTOU` while attempting to
restore the caller's foreground group; full interactive PTY handoff/restoration
is `[UNVERIFIED]` by the current native gate and is not a release claim.

## Network authority

Network access is denied by default because the base policy emits no network
allowance. With `--network`, the macOS compiler appends native outbound,
inbound, bind, and required system-service allowances. This is native Seatbelt
behavior; it does not prove another host's backend.

`--allow-net DOMAIN` is mutually exclusive with `--network`. Each value is an
exact lowercase-normalized ASCII DNS name with no trailing dot, wildcard,
userinfo, port, URL syntax, or IP literal. The target may issue only HTTPS
`CONNECT` to port 443. mbox starts a dependency-free parent-owned HTTP CONNECT
proxy on `127.0.0.1:EPHEMERAL` and `[::1]:EPHEMERAL`, overrides upper/lower HTTP(S) proxy variables,
and removes upper/lower `ALL_PROXY` and `NO_PROXY`. Seatbelt grants outbound
access only to that exact loopback port; direct public/private/IP sockets,
raw DNS, other loopback ports, inbound, and bind remain denied even if the
target changes its environment. The proxy bounds request headers, compares
the CONNECT authority and optional Host header exactly, resolves once through a
two-helper global cap with a bounded receive deadline, rejects any non-public
result (including private, local, reserved/test, IPv4-mapped IPv6, and all
non-global/special IPv6 prefixes), and dials the validated `SocketAddr`
directly. Connection workers and active tunnels are capped and registered with
RAII leases; finished workers are reaped during runtime. A resolver helper that
the OS keeps stuck beyond its deadline is not joined and retains its slot until
the resolver returns; process teardown terminates such helpers. It emits no
URL, header, credential, or body logs and keeps no persistent state. After the
CONNECT response, it must read a bounded first TLS ClientHello before sending
any application bytes upstream: the record must be TLS handshake data, contain
exactly one well-formed ASCII DNS `server_name`, and match the CONNECT
authority under ASCII case folding. Missing, duplicate, malformed,
plaintext/non-TLS, oversize, deadline-exceeded, and ECH (`0xfe0d`) handshakes
are rejected. The accepted ClientHello bytes are forwarded unchanged; later
TLS records are also forwarded unchanged. This proves the initial SNI boundary
for TLS 1.2 and TLS 1.3, but does not claim to parse a later TLS 1.3
HelloRetryRequest/second ClientHello.

## Failure contract

Release verification scripts have a separate startup contract. Their
executable shebang is the exact Darwin `/usr/bin/env -S -i` form, so Bash never
sees inherited startup controls. The nested runner allowlists only fixed
protocol paths, tool digests, and explicitly supplied `MBOX`/`PROBE` values;
ambient `PATH`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`,
`GLOBIGNORE`, and `BASH_XTRACEFD` are not propagated. Direct `bash script`
invocation is unsupported and fails the boundary-marker check; callers must
execute the script path or use the sanitized runner.

- malformed CLI input exits `2`;
- plan validation, trusted-launcher checks, invalid `--tmp`, and policy
  preparation failures before native exec exit `125`;
- a direct-exec target's exit code, signal status, and standard streams are
  returned by the native launcher boundary;
- exact-domain mode preserves direct streams and normal target exit codes,
  maps signal exits to `128 + signal`, forwards parent cancellation to the
  target group, observes the leader with Darwin `waitid(WNOWAIT)` before group
  cleanup/reap, then closes both listeners/tunnels and joins proxy workers;
- a launcher failure after `mbox` has replaced itself retains the launcher's
  native result. mbox does not claim to distinguish every such result from an
  equal target status.

## Residual risks

The backend intentionally leaves these boundaries explicit:

| Risk | Boundary and required response |
|---|---|
| Seatbelt is a private system interface | A source review is insufficient; run the native gate after every supported macOS or launcher update. |
| Path identity is not an inode pin | Canonicalization and final executable-write subtraction narrow the window, but a trusted caller must not mutate paths during preparation. |
| No resource scheduler | CPU, memory, process, wall-time, output, and disk limits belong to the caller or an upper execution layer. |
| Caller-owned temporary storage | `--tmp` is never created, chmodded, or deleted by mbox; the caller must provide and clean an existing 0700 directory. |
| Trusted launcher custody | `/usr/bin/sandbox-exec` and every parent directory are checked for canonical root-owned non-writable executables/directories; normal mode additionally checks `/bin/bash`, while strict mode checks the native target. Absence or failure is a setup error, never a fallback. |
| Helper lifecycle identity | The macOS contract uses the Darwin kernel PID/start tuple from `proc_pidinfo(PROC_PIDTBSDINFO)` with second and microsecond fields. Unknown or changed identity refuses signaling; an immediate capture failure uses only the just-created exact PID and fails if bounded TERM/KILL observation does not complete. The probe creates no descendants, so process-group ownership is not claimed. |
| Exact-mode setsid escape | Public Darwin process groups and audit sessions do not provide an unprivileged immutable descendant container/kill primitive. A target can `setsid(2)` and double-fork out of the owned PGID; AJ demonstrates and explicitly kills the test process. Do not use exact mode for untrusted descendants until a kernel-owned lifecycle primitive exists. |

These are product boundaries, not hidden recovery paths. A future change that
needs stronger identity, resource, or launcher guarantees requires a new
contract and native evidence.

## Verification ownership

The macOS platform gate is `./scripts/verify-macos.sh`. It first proves that
`sandbox-exec` can apply a deny-default profile on the current host, then runs
its platform-specific checks:

1. [`scripts/macos/static-check.sh`](../../scripts/macos/static-check.sh)
   checks macOS policy and surface boundaries and compiles the macOS helper.
2. [`tests/macos/contract.sh`](../../tests/macos/contract.sh) executes the
   shared behavior that is meaningful on macOS plus macOS native Seatbelt
   cases. It independently performs the locked binary and helper build so the
   native contract and `--runtime-only` mode do not depend on stale artifacts.
3. [`../MACOS_VERIFICATION.md`](../MACOS_VERIFICATION.md) records the operator
   command and evidence expected from a Darwin host.

The macOS contract includes only macOS-native scenarios. Linux verification
remains a separate Linux-host gate.
