# Architecture

`mbox` is one Rust executable with a shared request planner and two native
backends selected at compile time. The executable has no external Rust crate
dependencies. macOS uses the system Seatbelt launcher; Linux uses the system
Bubblewrap executable and a generated seccomp filter.

This document maps code responsibilities. The public behavior and security
limits remain canonical in [CONTRACT.md](CONTRACT.md).

## Execution flow

The arrows below show calls and the values passed between them. They do not
represent runtime verification evidence.

```text
main
  → cli::parse(argv)                         Action::Run(request)
  → ExecutionPlan::build(request)            canonical execution plan
  → platform::prepare(&plan)                 PreparedCommand
  → PreparedCommand::exec()
      ├─ Linux or direct macOS mode          close inherited FDs → native exec
      └─ exact-domain macOS mode             run_supervised → native child
```

Help and version actions print their result before planning or native setup.
The planner reads environment and filesystem metadata before native setup.
Each backend borrows the resulting plan. It prepares its native command and
owns any temporary setup resources. `PreparedCommand` then selects direct
replacement or the explicit macOS exact-domain supervision path.

## Source responsibilities

| Source | Responsibility |
|---|---|
| [`src/main.rs`](../src/main.rs) | Dispatch help/version/run and report CLI, setup, or supervised target results. |
| [`src/cli.rs`](../src/cli.rs) | Parse command syntax into a request without executing the target. |
| [`src/plan.rs`](../src/plan.rs) | Build the canonical plan and normalize the network request. |
| [`src/plan/environment.rs`](../src/plan/environment.rs) | Select environment values, reject launcher-sensitive inputs, and resolve the executable. |
| [`src/plan/roots.rs`](../src/plan/roots.rs) | Resolve access roots, inspect protected objects, and minimize path authorities. |
| [`src/platform/mod.rs`](../src/platform/mod.rs) | Route to the host backend, retain Linux setup files, and dispatch execution. |
| [`src/platform/fd.rs`](../src/platform/fd.rs) | Close inherited descriptors and make Linux setup descriptors inheritable. |
| [`src/platform/linux.rs`](../src/platform/linux.rs) | Reject unsupported modes, assemble Bubblewrap arguments, and transfer setup FD ownership. |
| [`src/platform/linux/bwrap.rs`](../src/platform/linux/bwrap.rs) | Validate the trusted Bubblewrap executable and minimum version. |
| [`src/platform/linux/mounts.rs`](../src/platform/linux/mounts.rs) | Pin mount sources and order readable, writable, and exact executable mounts. |
| [`src/platform/seccomp.rs`](../src/platform/seccomp.rs) | Generate the architecture-specific BPF program and seal its memfd. |
| [`src/platform/macos.rs`](../src/platform/macos.rs) | Validate launch inputs, start the optional proxy, and prepare the native command. |
| [`src/platform/macos/policy.rs`](../src/platform/macos/policy.rs) | Compile Seatbelt grants and final subtractions; supply path parameters separately. |
| [`src/platform/macos/macho.rs`](../src/platform/macos/macho.rs) | Perform bounded structural preflight for strict native targets. |
| [`src/platform/macos/supervisor.rs`](../src/platform/macos/supervisor.rs) | Own exact-mode signals, the initial target process group, waits, and terminal handoff/restoration. Also establish direct strict-mode process-group identity. |
| [`src/platform/macos_proxy.rs`](../src/platform/macos_proxy.rs) | Own ephemeral listeners, connection workers, active sockets, and CONNECT handling. |
| [`src/platform/macos_proxy/resolver.rs`](../src/platform/macos_proxy/resolver.rs) | Bound resolver helpers and validate resolved addresses before connection. |
| [`src/platform/macos_proxy/tls.rs`](../src/platform/macos_proxy/tls.rs) | Read and validate the bounded initial TLS ClientHello and its SNI. |

The shared plan does not duplicate native enforcement. Linux mount descriptors
and macOS Seatbelt path rules have different identity and lifetime contracts;
the backend owns those differences.

## State, I/O, and resource ownership

| Value or resource | Owner and lifetime |
|---|---|
| Raw `Request` | CLI parser, then consumed by the plan builder. |
| Canonical `ExecutionPlan` | Shared planner; borrowed without mutation by native preparation. |
| Linux mount files and seccomp memfd | Setup code, then `PreparedCommand`; descriptors survive until Bubblewrap consumes them during native execution. |
| macOS exact-domain listeners, workers, and active sockets | `ProxyRuntime`, retained by `PreparedCommand` and moved into the supervisor. |
| Exact-mode signal handlers and tty foreground group | Supervisor guards during supervision; the optional PTY check observes restoration for its tested interactions. |
| stdin, stdout, and stderr | Native launcher and target; mbox does not capture or persist target output. |
| Authorized target writes and macOS caller-supplied temporary directory | Caller and target; mbox provides no rollback or directory cleanup. |

The plan is the request's canonical configuration. Setup and supervision add
only transient runtime state. There is no persistent policy store, profile,
service, retry loop, or application log sink.

## Failure and verification boundaries

CLI rejection returns `2`; preparation or native-entry failure returns `125`.
No failed preparation selects a weaker launcher. Direct execution replaces
mbox, so subsequent launcher or target results remain native. The exact-domain
supervisor instead returns an observed target status after its owned cleanup.
See [I/O, lifecycle, and failure](CONTRACT.md#io-lifecycle-and-failure) for the
public result contract and [Non-goals](CONTRACT.md#non-goals) for caller-owned
controls.

Native evidence belongs to the OS and architecture that actually ran the
matching gate. Source review and cross compilation cannot substitute for
Seatbelt or Linux namespace/seccomp execution. Use the
[macOS](MACOS_VERIFICATION.md) and [Linux](LINUX_VERIFICATION.md) procedures;
their raw logs remain caller-owned evidence outside the repository.
