# mbox usage guide

This is the task-oriented guide for invoking `mbox`. The shared invariants are
defined in [`CONTRACT.md`](CONTRACT.md); build, cleanup, release, and incident
ownership are in [`OPERATIONS.md`](OPERATIONS.md).

## 1. Choose one authority mode

`mbox` receives one request, builds one immutable plan, enters the native
sandbox, and runs one target. There is no profile, configuration file, alias,
retry, daemon, or unsandboxed fallback.

| Intent | Invocation | Boundary |
|---|---|---|
| Offline work | omit network options | network is denied |
| Read an external path | add existing `--read PATH` | only that file/directory is added |
| Write output | add existing `--write PATH` | `/` cannot be writable; no rollback |
| Protect `.git` inside a write root | macOS `--deny-write PATH` | Linux exits setup `125` |
| Reach one HTTPS service | macOS `--allow-net DOMAIN` | exact DNS name, port 443, initial TLS SNI |
| Reach the native network | `--network` | full native network; no exact-domain filter |
| Give macOS a private temp root | existing caller-owned `--tmp PATH` | exact mode `0700`; caller cleanup |

The selected cwd and executable are always in the plan. Relative paths resolve
from the selected cwd. `--read` and `--write` add roots, and a write root
supersedes a contained read root. A `--write` root must already exist.

## 2. Build and invoke

From the repository root:

```sh
cargo build --release --locked
MBOX="$PWD/target/release/mbox"
"$MBOX" --version
"$MBOX" --help
```

The command form is always:

```text
mbox [OPTIONS] -- COMMAND [ARG...]
```

Every mbox option comes before the mandatory `--`. Everything after it is the
target command and its arguments, including strings that resemble mbox options.
The target is resolved from the selected environment's `PATH` or an explicit
path and must be an existing executable file.

## 3. Filesystem recipes

Prepare a workspace and existing output directory:

```sh
WORK="$PWD/work"
mkdir -p "$WORK/out"
MBOX="$PWD/target/release/mbox"
```

Read a selected input without network access:

```sh
"$MBOX" --cwd "$WORK" --read "$WORK/input.txt" -- \
  /bin/cat "$WORK/input.txt"
```

Write only to an existing output directory:

```sh
"$MBOX" --cwd "$WORK" --write "$WORK/out" -- \
  /bin/sh -c 'printf done > "$1"' sh "$WORK/out/result"
```

On macOS, protect an existing `.git` directory while allowing writes elsewhere
in the workspace:

```sh
"$MBOX" --cwd "$WORK" --write "$WORK" --deny-write "$WORK/.git" -- \
  /bin/sh -c 'printf result > "$1"' sh "$WORK/result"
```

`--deny-write` is applied after write grants and also protects a nonexistent
leaf, but Seatbelt remains path-based. It is not an inode pin against a trusted
caller changing paths during preparation. Linux must use a workspace/mount
layout that does not grant the protected path; the same option deliberately
fails setup instead of being ignored.

## 4. Network recipes

### Default: deny

Use no network flag for offline work. Native network calls are denied.

### Full native network

Use `--network` only when broad native network behavior is required:

```sh
"$MBOX" --cwd "$WORK" --network -- \
  /usr/bin/curl --fail --silent --show-error https://example.com/
```

It cannot be combined with `--allow-net` and is not a domain filter.

### Exact domain on macOS

Use exact ASCII DNS names for approved HTTPS services:

```sh
"$MBOX" --cwd "$WORK" --allow-net api.example.com -- \
  /usr/bin/curl --fail --silent --show-error https://api.example.com/health
```

The proxy accepts HTTPS `CONNECT` on port `443` only. Wildcards, URLs, ports,
IP literals, trailing dots, and non-ASCII names are rejected. Before forwarding,
the first TLS ClientHello must contain one well-formed SNI exactly matching the
CONNECT authority under ASCII case folding. This is an initial-SNI check, not
an HTTP `Host` check and not a claim to inspect a later TLS 1.3
HelloRetryRequest or encrypted application-layer hostname. A target that ignores
the proxy environment cannot create a direct network path.

Linux rejects `--allow-net` with setup `125`; there is no Linux exact-domain
fallback in this release.

## 5. Environment authority

The default environment is intentionally small. Add application inputs
explicitly:

```sh
"$MBOX" --cwd "$WORK" --set-env 'MODE=ci' --env TERM -- /usr/bin/env
```

`--env NAME` passes one existing host variable. `--set-env NAME=VALUE` sets an
exact value. `--inherit-env` passes all non-reserved, non-launcher-sensitive
variables and should be used only after reviewing the caller environment.

`PWD` and `TMPDIR` are mbox-owned. `OLDPWD`, `LD_*`, `DYLD_*`, `BASH_ENV`,
`ENV`, `SHELLOPTS`, `BASHOPTS`, `CDPATH`, and `GLOBIGNORE` cannot be delegated
through explicit environment options. Granted variables are visible to the
target; inheritance is not a secret-management system.

## 6. Temporary storage

On macOS, `--tmp` accepts only an existing directory owned by the invoking user
with exact mode `0700`. mbox does not create, chmod, or remove it:

```sh
CALLER_TMP=$(mktemp -d "${TMPDIR:-/tmp}/mbox-caller.XXXXXX")
chmod 700 "$CALLER_TMP"
trap 'rm -rf -- "$CALLER_TMP"' EXIT

"$MBOX" --cwd "$WORK" --tmp "$CALLER_TMP" -- /usr/bin/env
```

Review the exact temp path before using this cleanup trap in automation. On
Linux, `--tmp` exits `125`; the backend supplies anonymous sandbox-private
`/tmp` and `/dev/shm` for the process lifetime.

## 7. Platform capability matrix

| Capability | macOS | Linux |
|---|---|---|
| Backend | Seatbelt via `/usr/bin/sandbox-exec` | Bubblewrap 0.10+ + seccomp |
| Release architecture | native macOS host | `x86_64`, `aarch64` |
| Network default | deny | deny |
| `--network` | supported | supported |
| `--allow-net` | exact HTTPS CONNECT | setup `125` |
| `--deny-write` | supported | setup `125` |
| `--tmp` | existing 0700 caller directory | setup `125`; anonymous `/tmp` |
| Native proof | `./scripts/verify-macos.sh` on Darwin | `./scripts/verify-linux.sh` on Linux |

Native proof does not transfer between hosts. A macOS build or runtime result
cannot be called Linux proof, and vice versa.

## 8. Exit behavior

| Result | Status |
|---|---:|
| malformed CLI, missing `--`, invalid option syntax | `2` |
| plan, authority, trusted-launcher, policy, or native setup failure | `125` |
| target normal exit | target's exit code |
| target signal termination | native signal mapping; exact macOS mode reports `128 + signal` |

No setup error runs the target through a weaker or unsandboxed fallback. A
launcher failure after mbox has replaced itself retains the launcher's native
result.

## 9. Hard limits

- CPU, memory, process-count, wall-clock, output, and disk quotas belong to the
  caller or an upper runner.
- Authorized writes are ordinary host writes. A target may leave partial output;
  mbox has no transaction or rollback.
- Standard streams are direct. mbox does not capture, redact, or persist output.
- macOS Seatbelt is path-based and must be re-proven on each supported launcher
  or macOS update.
- macOS exact-domain cleanup owns the initial process group only. A target that
  calls `setsid(2)` and double-forks can escape it; see
  [`macos/SCENARIOS.md`](macos/SCENARIOS.md).
- Linux pins mount source descriptors during preparation, but the caller and
  host remain trusted before that boundary.
- `/usr/local`, home-managed toolchains, Xcode, and other non-system runtime
  data are not ambient. Add only required paths with `--read`; the optional
  macOS developer-tool recipe is in [`macos/CONTRACT.md`](macos/CONTRACT.md).
