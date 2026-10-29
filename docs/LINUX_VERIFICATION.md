# Linux verification

Run from the repository root:

```sh
set -o pipefail
log=$(mktemp "${TMPDIR:-/tmp}/mbox-linux-verification.XXXXXX")
echo "Linux verification log: $log"
./scripts/verify-linux.sh 2>&1 | tee "$log"
```

The supported Linux release architectures are `x86_64` and `aarch64`. Native
proof is architecture-specific: a successful macOS run or a build for another
target does not prove the Linux backend.

The full gate requires Linux, Rust/Cargo 1.85+, a C linker and libc development
files, Bash and GNU command-line tools, Bubblewrap 0.10+, unprivileged user
namespaces, and seccomp. Use the repository's pinned toolchain for current
release work; it includes `rustfmt`, `clippy`, and `llvm-tools`. The crate's
minimum compiler version and a successful cross check are separate from native
runtime evidence. The gate performs:

```text
shared static check
Linux static check
cargo fmt --check
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
locked debug build
Bubblewrap feature/user-namespace probe
Linux native A-AC contract (including fail-closed new-option checks)
```

`./scripts/verify-linux.sh --runtime-only` skips static, fmt, check, clippy, and
unit tests. It still performs a locked build, feature probe, helper build, and
native contract so stale binaries are not accepted as proof.

Exit `69` means the host lacks a required verifier prerequisite. Exit `1` means
a check or native contract failed. A successful macOS run is not Linux proof.

## Linux guest on a macOS host

Apple `container` can provide a real Linux kernel for the guest architecture.
Its CLI being installed is not enough: the service and a configured guest
kernel must both be available. Inspect `container system status` first. If no
kernel is configured, install the recommended kernel with the container tool;
when using a local kernel archive instead, verify the archive digest before
selecting its binary. Keep an existing working kernel configuration.

The following Bash recipe uses a disposable `aarch64` Linux environment on an
Apple Silicon host. It mounts the repository read-only, then copies source
into the guest's own filesystem so Linux builds do not replace macOS artifacts:

```bash
(
  set -euo pipefail
  container_id="mbox-linux-check-$$"
  container run --detach --rm --name "$container_id" --arch arm64 --cpus 2 --memory 2G \
    --mount "type=bind,source=$PWD,target=/source,readonly" \
    docker.io/library/rust:1.99.1-slim-trixie sleep infinity
  trap 'container stop "$container_id"' EXIT

  container exec "$container_id" /bin/bash -c '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends bubblewrap gcc libc6-dev procps util-linux
    rustup component add rustfmt clippy llvm-tools
    useradd --create-home --uid 1000 verifier
    mkdir /work
    tar -C /source --exclude=./target --exclude=./.git -cf - . | tar -C /work -xf -
    chown -R verifier:verifier /work
  '

  linux_log=$(mktemp "${TMPDIR:-/tmp}/mbox-linux-guest.XXXXXX")
  set +e
  container exec --user 1000 --env HOME=/home/verifier --workdir /work \
    "$container_id" /bin/bash -c \
    'sha256sum -c MANIFEST.sha256 && ./scripts/verify-linux.sh' \
    2>&1 | tee "$linux_log"
  linux_status=${PIPESTATUS[0]}
  set -e
  printf 'Linux gate status: %s; log: %s\n' "$linux_status" "$linux_log"
  exit "$linux_status"
)
```

The source copy must include the current uncommitted files and manifest when
validating a working tree. Keep its file hashes, image digest, `uname -a`,
`/etc/os-release`, Rust/Cargo versions, Bubblewrap version, and invoking UID
with the log. Do not replace the gate's feature probe or change namespace,
seccomp, mount, or failure expectations to accommodate a restricted guest.
If the probe cannot run, that environment remains unverified.

An `aarch64` guest pass proves only the tested Linux `aarch64` environment.
It does not prove Linux `x86_64`, Rosetta/emulated behavior, a different kernel,
or the Darwin backend. Run the gate natively on each deployment architecture.
