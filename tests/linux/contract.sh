#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
MBOX=${MBOX:-"$ROOT/target/debug/mbox"}
PROBE=${PROBE:-"$ROOT/target/mbox-linux-sandbox-probe"}
fail() {
  printf 'contract: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'contract %s: PASS\n' "$1"
}

[[ $(uname -s) == Linux ]] || fail "Linux contract must run on Linux"

expect_failure() {
  if "$@"; then
    fail "expected failure: $*"
  fi
}

expect_status() {
  local expected=$1
  shift
  local status
  set +e
  "$@"
  status=$?
  set -e
  [[ $status -eq $expected ]] || fail "expected status $expected, got $status: $*"
}

expect_busy_lock() {
  local output status
  set +e
  output=$("$PROBE" try-lock "$1" 2>&1)
  status=$?
  set -e
  [[ $status -eq 4 && $output == BUSY ]] ||
    fail "expected BUSY lock result, got status=$status output=$output"
}

TRUE=
for candidate in /usr/bin/true /bin/true; do
  if [[ -x $candidate ]]; then
    TRUE=$candidate
    break
  fi
done
[[ -n $TRUE ]] || fail "no executable true command found"

[[ -x $MBOX ]] || fail "mbox binary is not executable: $MBOX"
command -v rustc >/dev/null 2>&1 || fail "rustc is required to build the Linux probe"
mkdir -p "$(dirname "$PROBE")"
rustc --edition=2021 "$ROOT/tests/linux/helpers/sandbox_probe.rs" -o "$PROBE"

TEST_TMP_BASE=${MBOX_TEST_TMPDIR:-/var/tmp}
requested_tmp_base=$TEST_TMP_BASE
if ! TEST_TMP_BASE=$(readlink -f -- "$requested_tmp_base"); then
  fail "contract fixture root cannot be canonicalized: $requested_tmp_base"
fi
[[ -d $TEST_TMP_BASE && -w $TEST_TMP_BASE ]] ||
  fail "contract fixture root is not a writable directory: $requested_tmp_base"
case $TEST_TMP_BASE in
  /tmp|/tmp/*|/dev/shm|/dev/shm/*)
    fail "contract fixture root must be outside sandbox-private scratch: $TEST_TMP_BASE"
    ;;
esac
TMP=$(mktemp -d "$TEST_TMP_BASE/mbox-contract.XXXXXX")
SERVER_PID=
LAUNCHER_PID=
cleanup() {
  if [[ -n $SERVER_PID ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n $LAUNCHER_PID ]]; then
    kill -KILL "$LAUNCHER_PID" 2>/dev/null || true
    wait "$LAUNCHER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
WORK="$TMP/work"
OUTSIDE="$TMP/outside"
WRITE_DIR="$TMP/write"
mkdir -p "$WORK" "$OUTSIDE" "$WRITE_DIR"
printf 'inside\n' > "$WORK/inside.txt"
printf 'outside\n' > "$OUTSIDE/outside.txt"
printf 'old\n' > "$WRITE_DIR/file.txt"
printf 'sibling\n' > "$WRITE_DIR/sibling.txt"

# A
[[ "$("$MBOX" --cwd "$WORK" -- /bin/cat inside.txt)" == "inside" ]] || fail A
pass A

# B
expect_failure "$MBOX" --cwd "$WORK" -- /bin/cat "$OUTSIDE/outside.txt"
if [[ -e /etc/hostname ]]; then
  expect_failure "$MBOX" --cwd "$WORK" -- /bin/cat /etc/hostname
fi
pass B

# C
[[ "$("$MBOX" --cwd "$WORK" --read "$OUTSIDE/outside.txt" -- /bin/cat "$OUTSIDE/outside.txt")" == "outside" ]] || fail C
pass C

# D
expect_failure "$MBOX" --cwd "$WORK" -- /bin/sh -c 'printf denied > created.txt'
[[ ! -e "$WORK/created.txt" ]] || fail "D left a host artifact"
pass D

# E
"$MBOX" --cwd "$WORK" --write "$WRITE_DIR" -- /bin/sh -c 'printf allowed > "$1/new.txt"' sh "$WRITE_DIR"
[[ $(cat "$WRITE_DIR/new.txt") == allowed ]] || fail E
pass E

# F
"$MBOX" --cwd "$WORK" --write "$WRITE_DIR/file.txt" -- /bin/sh -c 'printf changed > "$1"' sh "$WRITE_DIR/file.txt"
[[ $(cat "$WRITE_DIR/file.txt") == changed ]] || fail "F file write"
expect_failure "$MBOX" --cwd "$WORK" --write "$WRITE_DIR/file.txt" -- /bin/sh -c 'printf bad > "$1"' sh "$WRITE_DIR/sibling.txt"
[[ $(cat "$WRITE_DIR/sibling.txt") == sibling ]] || fail "F sibling changed"
pass F

# G
[[ "$("$MBOX" --cwd "$WORK" -- /bin/pwd)" == "$(cd "$WORK" && pwd -P)" ]] || fail G
pass G

# H
"$MBOX" --cwd "$WORK" -- true
pass H

# I
if ! ARGV=$("$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" argv "a b" --value); then
  fail I
fi
EXPECTED=$(printf 'argv0:%s\n0:a b\n1:--value' "$PROBE")
[[ "$ARGV" == "$EXPECTED" ]] || fail I
pass I

# J
[[ "$(printf 'stdin-value' | "$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" stdin)" == stdin-value ]] || fail J
pass J

# K
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" streams >"$TMP/stdout" 2>"$TMP/stderr"
grep -qx STDOUT "$TMP/stdout" || fail "K stdout"
grep -qx STDERR "$TMP/stderr" || fail "K stderr"
pass K

# L
set +e
"$MBOX" --cwd "$WORK" -- /bin/sh -c 'exit 42'
status=$?
set -e
[[ $status -eq 42 ]] || fail "L status=$status"
pass L

# M
set +e
"$MBOX" --cwd "$WORK" -- /bin/sh -c 'kill -TERM $$'
status=$?
set -e
[[ $status -eq 143 ]] || fail "M status=$status"
pass M

# N
export MBOX_CONTRACT_SECRET=hidden
expect_failure "$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" env MBOX_CONTRACT_SECRET
unset MBOX_CONTRACT_SECRET
pass N

# O
MBOX_CONTRACT_VALUE=selected "$MBOX" --cwd "$WORK" --read "$PROBE" --env MBOX_CONTRACT_VALUE -- "$PROBE" env MBOX_CONTRACT_VALUE >"$TMP/env"
grep -qx selected "$TMP/env" || fail O
MBOX_CONTRACT_VALUE=inherited "$MBOX" --cwd "$WORK" --read "$PROBE" --inherit-env -- "$PROBE" env MBOX_CONTRACT_VALUE >"$TMP/env"
grep -qx inherited "$TMP/env" || fail "O inherit-env"
pass O

# P
"$MBOX" --cwd "$WORK" --read "$PROBE" --set-env MBOX_MODE='a b' -- "$PROBE" env MBOX_MODE >"$TMP/env"
grep -qx 'a b' "$TMP/env" || fail P
pass P

# Q
expect_failure "$MBOX" --set-env BASH_ENV=/tmp/inject -- "$TRUE"
expect_failure "$MBOX" --set-env DYLD_INSERT_LIBRARIES=/tmp/inject -- "$TRUE"
expect_failure "$MBOX" --set-env TMPDIR=/tmp -- "$TRUE"
printf 'touch %q\n' "$TMP/bash-env-marker" >"$TMP/bash-env"
BASH_ENV="$TMP/bash-env" "$MBOX" --inherit-env -- "$TRUE"
[[ ! -e "$TMP/bash-env-marker" ]] || fail "Q inherited BASH_ENV reached launcher"
pass Q

# Q2
exec 9<"$OUTSIDE/outside.txt"
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" fd-open 9 >"$TMP/fd"
exec 9<&-
grep -qx CLOSED "$TMP/fd" || fail Q2
pass Q2

# R
"$MBOX" --cwd "$WORK" -- /bin/sh -c 'test -d "$TMPDIR" && test -w "$TMPDIR" && : > "$TMPDIR/probe"'
pass R

# S
ln -s "$PROBE" "$TMP/probe-link"
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$TMP/probe-link" argv ok >"$TMP/symlink"
grep -qx "argv0:$TMP/probe-link" "$TMP/symlink" || fail "S argv0"
grep -qx '0:ok' "$TMP/symlink" || fail S
pass S

# T/U
PORT_FILE="$TMP/port"
"$PROBE" tcp-server "$PORT_FILE" &
server=$!
SERVER_PID=$server
for _ in $(seq 1 100); do
  [[ -s "$PORT_FILE" ]] && break
  sleep 0.02
done
[[ -s "$PORT_FILE" ]] || fail "server did not start"
port=$(cat "$PORT_FILE")
expect_failure "$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" tcp-connect "$port"
pass T
"$MBOX" --cwd "$WORK" --read "$PROBE" --network -- "$PROBE" tcp-connect "$port" >"$TMP/network"
wait "$server"
SERVER_PID=
grep -qx ok "$TMP/network" || fail U
pass U

# V
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" unix-socketpair | grep -qx OK
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" ptrace | grep -qx EPERM
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" io-uring | grep -qx EPERM
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" tty-injection >"$TMP/tty-injection"
[[ $(grep -cx EPERM "$TMP/tty-injection") -eq 2 ]] || fail "V tty injection"
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" tty-query | grep -qx ALLOWED
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" userns-disabled | grep -qx BLOCKED
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" unix-socket | grep -qx EPERM
UNIX_SOCKET="$TMP/host.sock"
UNIX_READY="$TMP/host-socket.ready"
UNIX_RECEIVED="$TMP/host-socket.received"
UNIX_STOP="$TMP/host-socket.stop"
"$PROBE" unix-dgram-server "$UNIX_SOCKET" "$UNIX_READY" "$UNIX_RECEIVED" "$UNIX_STOP" &
server=$!
SERVER_PID=$server
for _ in $(seq 1 100); do
  [[ -s "$UNIX_READY" ]] && break
  sleep 0.02
done
[[ -s "$UNIX_READY" ]] || fail "V Unix datagram server did not start"
"$MBOX" --cwd "$WORK" --read "$PROBE" --read "$TMP" -- \
  "$PROBE" unix-dgram-sendto "$UNIX_SOCKET" | grep -qx EPERM
: > "$UNIX_STOP"
set +e
wait "$server"
server_status=$?
set -e
SERVER_PID=
[[ $server_status -eq 0 ]] || fail "V host Unix socket received a sandbox datagram"
[[ ! -e "$UNIX_RECEIVED" ]] || fail "V host Unix socket effect escaped"
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" sendmsg | grep -qx EPERM
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" recvmsg | grep -qx EPERM
"$MBOX" --cwd "$WORK" --read "$PROBE" --network -- "$PROBE" ptrace | grep -qx EPERM
"$MBOX" --cwd "$WORK" --read "$PROBE" --network -- "$PROBE" tty-injection >"$TMP/tty-injection-network"
[[ $(grep -cx EPERM "$TMP/tty-injection-network") -eq 2 ]] || fail "V network tty injection"
pass V

# V2
LOCKFILE="$TMP/descendant.lock"
READY="$TMP/descendant.ready"
"$MBOX" --cwd "$WORK" --read "$PROBE" --write "$TMP" -- \
  /bin/sh -c '"$1" hold-lock "$2" "$3" & wait' \
  sh "$PROBE" "$LOCKFILE" "$READY" &
launcher=$!
LAUNCHER_PID=$launcher
for _ in $(seq 1 250); do
  [[ -s "$READY" ]] && break
  sleep 0.02
done
[[ -s "$READY" ]] || fail "V2 descendant did not acquire lock"
expect_busy_lock "$LOCKFILE"
kill -TERM "$launcher"
set +e
wait "$launcher"
status=$?
set -e
LAUNCHER_PID=
[[ $status -eq 143 ]] || fail "V2 launcher status=$status"
released=
for _ in $(seq 1 250); do
  set +e
  lock_output=$("$PROBE" try-lock "$LOCKFILE" 2>&1)
  lock_status=$?
  set -e
  if [[ $lock_status -eq 0 && $lock_output == LOCKED ]]; then
    released=1
    break
  fi
  if [[ $lock_status -ne 4 || $lock_output != BUSY ]]; then
    fail "V2 lock probe failed: status=$lock_status output=$lock_output"
  fi
  sleep 0.02
done
[[ -n $released ]] || fail "V2 descendant retained lock after launcher cancellation"
pass V2

# W
MARKER="$TMP/marker"
expect_failure "$MBOX" --read "$TMP/missing" -- /bin/sh -c 'touch "$1"' sh "$MARKER"
[[ ! -e "$MARKER" ]] || fail W
expect_failure "$MBOX" --write / -- "$TRUE"
pass W

# X
"$MBOX" --cwd "$WORK" -- "$TRUE"
"$MBOX" --cwd "$WORK" -- "$TRUE"
pass X

# Y
"$MBOX" --cwd "$WORK" -- /bin/sh -c 'sleep 0.1' &
left=$!
"$MBOX" --cwd "$WORK" -- /bin/sh -c 'sleep 0.1' &
right=$!
wait "$left" "$right"
pass Y

# Z
expect_failure "$MBOX" --cwd "$WORK" -- /bin/sh -c 'umask 000; printf partial > forbidden'
[[ ! -e "$WORK/forbidden" ]] || fail Z
pass Z

# AA
EXEC_DIR="$TMP/executable-write-root"
mkdir "$EXEC_DIR"
EXECUTABLE="$EXEC_DIR/probe"
SIBLING="$EXEC_DIR/sibling"
REPLACEMENT="$EXEC_DIR/replacement"
cp "$PROBE" "$EXECUTABLE"
printf 'sibling\n' > "$SIBLING"
"$MBOX" --cwd "$WORK" --write "$EXEC_DIR" -- "$EXECUTABLE" remove-file "$SIBLING"
[[ ! -e "$SIBLING" ]] || fail "AA sibling remained"
printf 'sibling\n' > "$SIBLING"
expect_failure "$MBOX" --cwd "$WORK" --write "$EXEC_DIR" -- "$EXECUTABLE" remove-file "$EXECUTABLE"
cp "$PROBE" "$REPLACEMENT"
expect_failure "$MBOX" --cwd "$WORK" --write "$EXEC_DIR" -- \
  "$EXECUTABLE" rename-file "$REPLACEMENT" "$EXECUTABLE"
[[ -e "$REPLACEMENT" ]] || fail "AA replacement was consumed"
[[ -x "$EXECUTABLE" ]] || fail "AA executable was removed"
cmp "$PROBE" "$EXECUTABLE" >/dev/null || fail "AA executable changed"
pass AA

# AB: macOS-only exact-network and write-subtraction options fail closed on
# Linux before the target can run. Linux native behavior is not claimed here;
# this is source/runtime coverage for the explicit setup contract.
ALLOW_NET_MARKER="$TMP/allow-net-target-ran"
expect_status 125 "$MBOX" --cwd "$WORK" --allow-net example.com -- /bin/sh -c \
  'touch "$1"' sh "$ALLOW_NET_MARKER"
[[ ! -e "$ALLOW_NET_MARKER" ]] || fail "AB allow-net target ran on Linux"
DENY_WRITE_MARKER="$TMP/deny-write-target-ran"
expect_status 125 "$MBOX" --cwd "$WORK" --deny-write "$WRITE_DIR" -- /bin/sh -c \
  'touch "$1"' sh "$DENY_WRITE_MARKER"
[[ ! -e "$DENY_WRITE_MARKER" ]] || fail "AB deny-write target ran on Linux"
pass AB

printf 'linux contract A-AB: PASS\n'
