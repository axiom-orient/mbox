# Linux native scenarios

`tests/linux/contract.sh` is the executable contract.

| ID | Expected observation |
|---|---|
| A-C | cwd and explicit read roots work; unrelated host reads fail |
| D-F | host writes outside private scratch fail by default; explicit directory/file host writes are exact, including a writable child under read-only cwd |
| G-I | canonical cwd, PATH resolution, argv bytes, and original argv0 hold |
| J-M | stdin/stdout/stderr and native exit/signal results are preserved |
| N-Q | environment is minimal; selected values pass; launcher variables fail |
| Q2 | inherited descriptor 9 is closed |
| R-S | anonymous TMPDIR works; canonical executable keeps original argv0 |
| T-U | TCP fails without `--network` and succeeds with it |
| V | ptrace/io_uring/TIOCSTI/TIOCLINUX and endpoint socket syscalls return EPERM; an exposed host Unix socket receives no datagram; normal ioctl and AF_UNIX socketpair remain usable; nested user namespaces stay blocked |
| V2 | killing the launcher releases a host-visible lock held by a descendant |
| W-Z | invalid setup is fail-closed; repeated/concurrent requests have no hidden state; denied writes leave no file |
| AA | a writable parent permits sibling removal but exact executable removal and replacement both fail |

The V2 oracle uses an inode lock, not a PID written from the sandbox PID
namespace. Contract fixtures default to `/var/tmp`, outside the sandbox-private
`/tmp`, and canonicalize and reject `/tmp` and `/dev/shm` roots and subpaths so
exact host-write checks cannot be satisfied by ephemeral scratch.
