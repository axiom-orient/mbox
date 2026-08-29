# macOS contract scenarios

Run these scenarios through `./scripts/verify-macos.sh`. The native contract
performs a locked binary build, builds its macOS helper, and executes against
the native Seatbelt launcher. The IDs below cover only macOS-owned behavior.

| ID | User intent | Expected macOS result |
|---|---|---|
| A | Read a file in cwd | succeeds |
| B | Read an unrelated host file | denied |
| C | Add one external read root | succeeds only for that root |
| D | Write in cwd without authority | denied, no host artifact |
| E | Add a writable directory | create/update succeeds there |
| F | Add one writable file | that file succeeds; sibling write fails |
| G | Select cwd | target observes canonical cwd |
| H | Resolve a PATH command | selected executable runs |
| I | Pass spaces and option-like argv | exact bytes/positions preserved |
| J | Pipe stdin | target receives it directly |
| K | Emit stdout/stderr | both streams remain separate |
| L | Exit 42 | caller observes 42 |
| M | Terminate by SIGTERM | caller observes native signal status |
| N | Read an unselected env variable | absent |
| O | Pass one existing env variable | present |
| P | Set one env variable | exact value present |
| Q | Inject launcher variables | rejected before target execution |
| Q2 | Inherit FD 9 from parent | target observes it closed |
| R | Omit `--tmp` | target observes no `TMPDIR` and has no temporary write authority |
| R2 | Supply a caller-owned `--tmp` | existing 0700 directory is exported and writable; no `.mbox-*` scratch is created |
| R3 | Supply missing, non-directory, wrong-mode, or special-bit `--tmp` | exit 125; target does not run |
| S | Invoke a command through a symlink | canonical executable runs; argv0 remains original |
| T | Connect without `--network` | denied |
| U | Connect with `--network` | succeeds when a host endpoint exists |
| AF | Exact-domain HTTPS CONNECT and hostile-proxy abuse | allowed normalized domain succeeds; unlisted, trailing-dot, malformed, IP, non-443, environment tamper, private-resolution, raw UDP/TCP DNS, direct public-IP, other loopback, bind, closed IPv4/IPv6 listeners, IPv6 same-port bind, and overflow/RST bypasses fail; bounded abuse recovers normal CONNECT and fd count |
| AF-SNI | Exact CONNECT authority and TLS endpoint identity | raw CONNECT with matching raw SNI succeeds; the same raw CONNECT with avatars SNI is rejected before ClientHello forwarding; parser covers fragmented records, absent/duplicate/malformed SNI, ECH, and bounds |
| AG | Cancel an active exact-domain tunnel | target's initial process group, listeners, workers, and tunnel have no immediate or delayed survivor; this is scoped to descendants that remain in that group |
| AI | Normal exact-domain leader exit and SIGINT | same-group background descendant is removed before leader reap; SIGINT maps to 130 and removes active same-group descendant immediately and after delay |
| V | Create an unnamed Unix socket pair | succeeds inside the Seatbelt sandbox |
| W | Supply invalid authority | exit 125; target does not run |
| X | Run the same request twice | no hidden state changes the result |
| AK | Strict direct native target and thread-only work | canonical target `argv[0]` is observed; a thread-only target succeeds without Bash |
| AL | Strict child/other-image boundary | fork/vfork/`posix_spawn`/background/setsid attempts report denial with no marker; `/bin/bash` re-exec is denied |
| AM | Strict visible process custody | same PID/start tuple is terminated and has no immediate or delayed survivor |
| AN | Strict setup rejection | script/interpreter shim and exact-domain proxy fail setup `125` |
| AO | Strict structural-image rejection | magic-only image fails setup `125` before target execution |
| AP | Strict fat-image endian/width rejection | complete CIGAM32/CIGAM64 images and a host-CPU Thin32 image fail setup `125` before Seatbelt |
| AQ | Strict same-image self-reexec | the native helper `execve`s its exact canonical image once; before/after Darwin PID/start tuples and image paths match |
| Y | Run requests concurrently | direct executions do not share hidden mbox temp state |
| Z | Trigger a denied write | no partial host file remains |
| AA | Read a sibling beside the executable | denied unless that exact sibling is explicitly read |
| AB | Canonicalize an explicitly read nested path | canonicalization succeeds; sibling and parent data remain denied |
| AC | Attempt TIOCSTI on a private controlling PTY | returns `EPERM`; normal tty ioctl support remains available; exact-mode interactive PTY handoff/restoration is `[UNVERIFIED]` |
| AD | Run an executable inside a writable parent | sibling removal succeeds; exact executable removal and replacement both fail |
| AE | Clean up an owned TCP helper on normal and EXIT paths | Darwin kernel `proc_pidinfo(PROC_PIDTBSDINFO)` PID plus `pbi_start_tvsec`/`pbi_start_tvusec`; capture-failure exact-PID cleanup, mismatch refusal, bounded TERM/KILL/reap, immediate/delayed no-survivor checks; no process-group claim |
| AH | Subtract writes at nonexistent `.git`, directory, file pointer, and hardlink aliases | create/write/remove/rename/replacement at protected paths fail; writable siblings succeed; preflight rejects protected/executable hardlinks and in-sandbox link creation |
| AJ | Escape lifecycle ownership with `setsid(2)` and double-fork | the native probe records an escaped process outside the initial PGID; the test captures its Darwin PID/start tuple, rechecks that tuple before KILL and during disappearance polling, does not reap it because it is not a child, and documents that exact mode is not a no-survivor guarantee for untrusted descendants |

## Flow under test

```text
choose explicit cwd/read/write/network authority and optional caller-owned tmp
  → reject malformed or unavailable input
  → canonicalize and build one immutable plan
  → compile the deny-default Seatbelt policy with metadata-only root ancestors
  → subtract writes to the exact executable, caller-protected paths, and terminal-input injection after broad grants
  → in strict mode, validate Mach-O, append final fork/exec subtraction, observe or establish pgid == pid, and direct-exec the canonical target
  → for exact domains, bind parent-owned ephemeral CONNECT listeners on both loopback families and grant Seatbelt only that port
  → close inherited descriptors and supervise only the exact-domain target group
  → observe direct stdio, status, and signal behavior (interactive exact-mode PTY restoration remains `[UNVERIFIED]`)
  → close both listeners/tunnels and join workers; target-group cleanup is bounded through TERM then KILL observation, but does not own setsid escapes
```

`tests/macos/contract.sh` is the executable oracle and
`tests/macos/helpers/sandbox_probe.rs` is its small macOS-compatible probe.
A successful macOS run does not close the Linux gate.

Scenarios AK–AP cover the strict `--no-child-processes` path. The native
helper attempts each process-creation API and a `/bin/bash` re-exec; the
contract checks denial evidence, absence of a writable marker immediately and
after a delay, and the visible PID/start tuple for a thread-only hold. Strict
`setsid(2)` failure comes from the established process-group-leader invariant;
the scenario does not claim an independent Seatbelt setsid permission. AO
passes only a four-byte Mach-O magic file and proves structural preflight
returns setup `125` without executing it. AP passes complete little-endian
CIGAM32/CIGAM64 tables around the native helper and separately exercises the
host-CPU Thin32 contradiction; all fail before Seatbelt.

Scenario AQ is the positive strict-exec oracle. The helper prints its Darwin
PID/start tuple, directly `execve`s the exact canonical helper image with an
explicit one-time argv phase marker, and prints the tuple again after
replacement. The contract requires equal tuples and two matching canonical
image lines. No fork, child, or Bash launcher is involved; AL continues to
cover the other-image and process-creation denials.

Scenario AE is the repository's lifecycle regression. It records the helper's
PID and Darwin kernel start tuple from `proc_pidinfo(PROC_PIDTBSDINFO)`
immediately after launch. It refuses TERM or KILL when the tuple is unknown or
does not match, and exercises bounded exact-`$!` TERM/KILL/reap cleanup when
capture fails before an identity-dependent trap. It also checks no survivor
immediately and after a short delay. The helper branch under test creates no
descendants; the contract therefore deliberately does not claim process-group
ownership.

Scenario AF uses the host's `/usr/bin/curl` only as a network-dependent positive
proof for `example.com`; its failures are still deterministic Seatbelt/proxy
policy checks. It also drives raw UDP/TCP DNS, direct-IP, private-resolution,
other-loopback, listener-close, partial-header/RST, and worker-overflow cases;
the helper samples the owning process's actual live Darwin file-descriptor
entries through `PROC_PIDLISTFDS` while abuse is active. It does not use
`pbi_nfiles`, which is the descriptor-table capacity rather than the number of
currently live descriptors.
AF-SNI uses curl's `--connect-to` form to keep `avatars.githubusercontent.com`
in the TLS SNI while the proxy CONNECT authority is
`raw.githubusercontent.com`; the exact SNI parser rejects that shared-IP-style
confusion, while matching raw CONNECT/SNI remains a network-dependent positive.
Scenario AG creates an active proxy tunnel with the helper and terminates the
mbox parent, then checks the owned child immediately and after a short delay.
Scenario AI covers normal leader exit with a same-group background descendant
and a separate SIGINT active-tunnel cancellation. Scenario AH runs protected-path
mutations under a writable parent, including hardlink preflight and link
creation, and verifies an unrelated sibling remains writable.
Scenario AJ deliberately calls `setsid(2)` and double-forks, records the
escaped PID after mbox returns, captures its Darwin PID/start tuple, and kills
that exact test PID only while the tuple still matches. It polls the same
identity until it disappears and does not reap it because it is not the
contract shell's child. It is a negative ownership proof: public Darwin
process groups and audit sessions do not provide an unprivileged immutable
descendant container/kill primitive.
