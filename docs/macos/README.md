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

The backend depends on a macOS system interface without a public compatibility
guarantee. The repository therefore makes no forward-compatibility claim from
source inspection alone. Each supported macOS release must pass:

```sh
./scripts/verify-macos.sh
```

A Linux build or static policy review is not macOS native proof.

The repeatable Darwin procedure is in
[`../MACOS_VERIFICATION.md`](../MACOS_VERIFICATION.md). Its command output and
host identity are caller-owned release evidence and must be stored outside the
repository as described in [`../OPERATIONS.md`](../OPERATIONS.md). Keep that
evidence separate from this platform contract: it is a host/run record, not a
new runtime authority or a compatibility promise.
