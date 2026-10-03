# mbox

`mbox` runs one command with explicit filesystem, environment, and network
authority. It is a dependency-free Rust binary with native backends:

- macOS: Seatbelt through the trusted `/usr/bin/sandbox-exec` launcher;
- Linux: Bubblewrap 0.10+ with an mbox-owned seccomp filter.

It is an authority boundary, not a VM, container image system, daemon, resource
scheduler, or persistent service. There are no profiles, configuration files,
compatibility fallbacks, logs, or hidden state.

## Quick start

```sh
cargo build --release --locked
target/release/mbox -- /bin/echo hello
```

The `--` separator is mandatory. Select `--read` and `--write` roots explicitly;
network is denied unless `--network` or macOS exact-domain `--allow-net` is
chosen. Invalid CLI input exits `2`; validation or native setup failures exit
`125`. See [`docs/USAGE.md`](docs/USAGE.md) for recipes and
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for build, deployment, and runbook
practice.

On macOS, `--no-child-processes` is the strict single-image mode used when the
caller needs a native Mach-O target with no target-created fork/vfork/
`posix_spawn`/background child and no exec of another image. The target is
launched directly by Seatbelt with canonical-path `argv[0]`; bounded Mach-O
preflight rejects malformed images, scripts, interpreter shims, and fat files
without a current-host executable slice. The flag establishes the mbox process as its
own process-group leader before replacement, so a direct `setsid(2)` attempt
fails. It cannot be combined with macOS exact-domain `--allow-net`; Linux
returns setup `125`, and Windows is unsupported at compile time.

## Security boundary in one view

The target receives direct stdin/stdout/stderr and native exit status. mbox
closes inherited file descriptors above `2`, keeps the selected executable
read-only even inside a writable parent, and does not roll back partial target
writes. Network is denied by default. macOS exact-domain mode checks the initial
TLS ClientHello SNI, not a later encrypted application hostname; its process
group cleanup does not own a `setsid(2)`/double-fork escape. CPU, memory, time,
output, and disk limits belong to the caller. The complete invariant set is in
[`docs/CONTRACT.md`](docs/CONTRACT.md).

## Platform choice

| Need | macOS | Linux |
|---|---|---|
| Default offline execution | Seatbelt | Bubblewrap + seccomp |
| Full native network | `--network` | `--network` |
| Exact HTTPS domain | `--allow-net DOMAIN` | setup `125` |
| Subtract a writable path, including `.git` | `--deny-write PATH` | setup `125` |
| Caller-supplied temp directory | existing 0700 `--tmp PATH` | setup `125`; anonymous `/tmp` |
| Strict single native image | `--no-child-processes` | setup `125` |

Linux release support is `x86_64` and `aarch64`. `/usr/local`, home-managed
toolchains, and similar runtime data are not ambient; add only required paths
with `--read`. Native proof is host-specific and uses the matching verifier.

## Verification boundary

The shared source and contracts are canonical on both hosts. Native proof is
not transferable: only the Darwin gate proves Seatbelt behavior, and only the
Linux gate proves Bubblewrap, namespaces, and kernel seccomp behavior. A
blocked prerequisite exits 69 and is never replaced by a weaker launcher.

The command and evidence checklist are maintained in
[`docs/MACOS_VERIFICATION.md`](docs/MACOS_VERIFICATION.md). Exact-domain
lifecycle ownership is limited to the target's initial process group; scenario
AJ records the `setsid(2)`/double-fork limitation.

## Documentation map

- [`docs/USAGE.md`](docs/USAGE.md) — CLI recipes, authority selection, platform
  capabilities, exits, and hard limits.
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — preflight, release identity,
  authority review, logs, cleanup, verification, upgrades, rollback, and triage.
- [`docs/CONTRACT.md`](docs/CONTRACT.md) — shared public execution contract.
- [`docs/SCENARIOS.md`](docs/SCENARIOS.md) — native scenario router.
- [`docs/macos/README.md`](docs/macos/README.md) and
  [`docs/MACOS_VERIFICATION.md`](docs/MACOS_VERIFICATION.md) — macOS index/gate.
- [`docs/linux/CONTRACT.md`](docs/linux/CONTRACT.md) and
  [`docs/LINUX_VERIFICATION.md`](docs/LINUX_VERIFICATION.md) — Linux contract/gate.

## Verification

```sh
./scripts/verify.sh             # full gate for the current host
./scripts/verify-macos.sh       # Darwin gate
./scripts/verify-linux.sh       # Linux gate
```

`--runtime-only` skips formatting, lint, and Rust unit tests, but still performs
a locked debug build and the native contract. A successful build on one OS is
not proof for the other backend.

## GitHub 배포 분류

mbox의 주 제품은 사람이 직접 실행하는 native sandbox CLI이므로 목표 조직은 [`AxiomOrient`](https://github.com/AxiomOrient)다. 현재 `axiom-orient` 원격은 외부 소비자와 링크를 확인한 뒤 안전하게 transfer하기 전까지 유지한다.
