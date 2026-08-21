# Verification boundaries

`mbox` has one shared Rust source tree and two native backends. Source, shared
contracts, and static checks may be reviewed and changed on either host.
Native runtime evidence is platform-specific:

- macOS proof comes only from `./scripts/verify-macos.sh` on Darwin;
- Linux proof comes only from `./scripts/verify-linux.sh` on Linux.

A successful static check, build, or run on one platform is not proof for the
other platform. Never replace a blocked native gate with a mock, fallback, or
weaker launcher. Keep the fail-closed public contract, direct stdio/status
semantics, and the absence of profiles, services, SDKs, and persistent state.

Platform-owned artifacts are organized by responsibility rather than edit
permission:

- macOS: `src/platform/macos*`, `docs/macos/**`, `tests/macos/**`,
  `scripts/macos/**`, `docs/MACOS_VERIFICATION.md`, `scripts/verify-macos.sh`;
- Linux: `src/platform/linux.rs`, `src/platform/seccomp.rs`, `docs/linux/**`,
  `tests/linux/**`, `scripts/linux/**`, `docs/LINUX_VERIFICATION.md`,
  `scripts/verify-linux.sh`;
- shared: the remaining source, contracts, routing, and static verification.
