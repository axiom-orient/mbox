#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"

fail() {
  printf 'contract: FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'contract %s: PASS\n' "$1"
}

expect_failure() {
  if "$@"; then
    fail "expected failure: $*"
  fi
}

expect_status() {
  local expected=$1
  shift
  set +e
  "$@"
  local status=$?
  set -e
  [[ $status -eq $expected ]] || fail "expected status $expected, got $status: $*"
}

[[ $(uname -s) == Darwin ]] || fail "macOS contract must run on Darwin"

MBOX=${MBOX:-"$ROOT/target/debug/mbox"}
PROBE=${PROBE:-"$ROOT/target/mbox-macos-sandbox-probe"}

LIFECYCLE_POLL_LIMIT=100
LIFECYCLE_POLL_SECONDS=0.02
LIFECYCLE_POST_WATCH_SECONDS=0.1

TRUE=
for candidate in /usr/bin/true /bin/true; do
  if [[ -x $candidate ]]; then
    TRUE=$candidate
    break
  fi
done
[[ -n $TRUE ]] || fail "no executable true command found"

cargo build --quiet --locked --manifest-path "$ROOT/Cargo.toml"
rustc --edition=2021 "$ROOT/tests/macos/helpers/sandbox_probe.rs" -o "$PROBE"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/mbox-macos-contract.XXXXXX")
SERVER_PID=
SERVER_IDENTITY=
SERVER_WAIT_STATUS=
ESCAPED_PID=
ESCAPED_IDENTITY=
ESCAPED_IDENTITY_OBSERVED=

# The probe's tcp-server branch does not fork or daemonize. Keep cleanup scoped
# to the captured PID and Darwin kernel start identity; do not infer ownership
# from a name or process group that may contain unrelated work.
process_identity() {
  local pid=$1
  local output
  local identity_status

  if [[ ${IDENTITY_CAPTURE_FORCE_FAIL:-0} == 1 ]]; then
    return 2
  fi
  if output=$("$PROBE" process-identity "$pid" 2>/dev/null); then
    [[ "$output" =~ ^[0-9]+\|[0-9]+\|[0-9]+$ ]] || return 2
    printf '%s' "$output"
    return 0
  else
    identity_status=$?
  fi
  [[ $identity_status -eq 3 ]] && return 1
  return 2
}

observe_server_identity() {
  local current
  local identity_status

  IDENTITY_OBSERVED=
  if current=$(process_identity "$SERVER_PID" 2>/dev/null); then
    IDENTITY_OBSERVED=$current
    if [[ "$current" == "$SERVER_IDENTITY" ]]; then
      return 0
    fi
    printf 'contract: lifecycle identity changed: expected `%s`, observed `%s`\n' \
      "$SERVER_IDENTITY" "$current" >&2
    return 3
  else
    identity_status=$?
  fi
  if [[ $identity_status -eq 1 ]]; then
    return 1
  fi
  printf 'contract: lifecycle identity unavailable for PID %s; refusing signal\n' \
    "$SERVER_PID" >&2
  return 2
}

owned_server_live() {
  observe_server_identity
}

wait_for_server_exit() {
  local iteration=0
  local live_status

  while [[ $iteration -lt $LIFECYCLE_POLL_LIMIT ]]; do
    if owned_server_live; then
      sleep "$LIFECYCLE_POLL_SECONDS"
    else
      live_status=$?
      [[ $live_status -eq 1 ]] && return 0
      return "$live_status"
    fi
    iteration=$((iteration + 1))
  done
  return 1
}

reap_server() {
  SERVER_WAIT_STATUS=0
  wait "$SERVER_PID" 2>/dev/null || SERVER_WAIT_STATUS=$?
  [[ $SERVER_WAIT_STATUS -ne 127 ]] || {
    printf 'contract: lifecycle wait could not reap PID %s\n' "$SERVER_PID" >&2
    return 1
  }
  return 0
}

wait_for_exact_pid_exit() {
  local iteration=0

  while [[ $iteration -lt $LIFECYCLE_POLL_LIMIT ]]; do
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      sleep "$LIFECYCLE_POLL_SECONDS"
    else
      return 0
    fi
    iteration=$((iteration + 1))
  done
  return 1
}

assert_no_exact_pid_survivor() {
  local context=$1
  local pid=$SERVER_PID

  if kill -0 "$pid" 2>/dev/null; then
    printf 'contract: lifecycle %s exact-PID survivor: %s\n' "$context" "$pid" >&2
    return 1
  fi
  printf 'contract lifecycle %s: exact-PID no survivor immediate\n' "$context"
  sleep "$LIFECYCLE_POST_WATCH_SECONDS"
  if kill -0 "$pid" 2>/dev/null; then
    printf 'contract: lifecycle %s delayed exact-PID survivor: %s\n' "$context" "$pid" >&2
    return 1
  fi
  printf 'contract lifecycle %s: exact-PID no survivor delayed\n' "$context"
}

assert_no_server_survivor() {
  local context=$1
  local identity_status

  if observe_server_identity; then
    printf 'contract: lifecycle %s survivor: `%s`\n' "$context" "$IDENTITY_OBSERVED" >&2
    return 1
  else
    identity_status=$?
  fi
  if [[ $identity_status -ne 1 ]]; then
    printf 'contract: lifecycle %s could not prove no survivor (identity status %s)\n' \
      "$context" "$identity_status" >&2
    return 1
  fi
  printf 'contract lifecycle %s: no survivor immediate\n' "$context"
  sleep "$LIFECYCLE_POST_WATCH_SECONDS"
  if observe_server_identity; then
    printf 'contract: lifecycle %s delayed survivor: `%s`\n' \
      "$context" "$IDENTITY_OBSERVED" >&2
    return 1
  else
    identity_status=$?
  fi
  if [[ $identity_status -ne 1 ]]; then
    printf 'contract: lifecycle %s delayed no-survivor proof unavailable (identity status %s)\n' \
      "$context" "$identity_status" >&2
    return 1
  fi
  printf 'contract lifecycle %s: no survivor delayed\n' "$context"
}

cleanup_unidentified_server() {
  local context=$1
  local wait_status

  [[ -n "$SERVER_PID" ]] || return 0
  printf 'contract lifecycle %s: identity capture failed; exact PID TERM pid=%s\n' \
    "$context" "$SERVER_PID"
  kill -TERM "$SERVER_PID" 2>/dev/null || true
  if wait_for_exact_pid_exit; then
    printf 'contract lifecycle %s: exact PID TERM wait completed\n' "$context"
  else
    wait_status=$?
    [[ $wait_status -eq 1 ]] || return "$wait_status"
    printf 'contract lifecycle %s: exact PID KILL pid=%s after bounded TERM wait\n' \
      "$context" "$SERVER_PID"
    kill -KILL "$SERVER_PID" 2>/dev/null || true
    wait_for_exact_pid_exit || {
      printf 'contract: lifecycle %s exact PID survived bounded KILL\n' "$context" >&2
      return 1
    }
    printf 'contract lifecycle %s: exact PID KILL wait completed\n' "$context"
  fi
  reap_server || return 1
  assert_no_exact_pid_survivor "$context" || return 1
  printf 'contract lifecycle %s: exact PID reaped status=%s\n' \
    "$context" "$SERVER_WAIT_STATUS"
  SERVER_PID=
  SERVER_IDENTITY=
}

cleanup_server() {
  local context=$1
  local wait_status

  [[ -n "$SERVER_PID" ]] || return 0
  if [[ -z "$SERVER_IDENTITY" ]]; then
    cleanup_unidentified_server "$context"
    return
  fi
  if observe_server_identity; then

    printf 'contract lifecycle %s: TERM pid=%s identity=%s\n' \
      "$context" "$SERVER_PID" "$SERVER_IDENTITY"
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    if wait_for_server_exit; then
      printf 'contract lifecycle %s: TERM wait completed\n' "$context"
    else
      wait_status=$?
      [[ $wait_status -eq 1 ]] || return "$wait_status"
      if observe_server_identity; then
        printf 'contract lifecycle %s: KILL pid=%s after bounded TERM wait\n' \
          "$context" "$SERVER_PID"
        kill -KILL "$SERVER_PID" 2>/dev/null || true
        wait_for_server_exit || return $?
        printf 'contract lifecycle %s: KILL wait completed\n' "$context"
      else
        wait_status=$?
        [[ $wait_status -eq 1 ]] || return "$wait_status"
        printf 'contract lifecycle %s: TERM observed exit after bounded wait\n' "$context"
      fi
    fi
  else
    wait_status=$?
    [[ $wait_status -eq 1 ]] || return "$wait_status"
    printf 'contract lifecycle %s: leader already exited\n' "$context"
  fi

  reap_server || return 1
  assert_no_server_survivor "$context" || return 1
  printf 'contract lifecycle %s: reaped status=%s\n' "$context" "$SERVER_WAIT_STATUS"
  SERVER_PID=
  SERVER_IDENTITY=
}

# AJ deliberately creates a descendant that is no longer in mbox's initial
# process group. It is not mbox-owned, so this contract records the boundary
# and only cleans the test process after a fresh Darwin PID/start-tuple check.
# Unlike a child of the shell, it cannot be reaped here.
observe_escaped_identity() {
  local current
  local identity_status

  ESCAPED_IDENTITY_OBSERVED=
  if current=$(process_identity "$ESCAPED_PID" 2>/dev/null); then
    ESCAPED_IDENTITY_OBSERVED=$current
    if [[ "$current" == "$ESCAPED_IDENTITY" ]]; then
      return 0
    fi
    printf 'contract: AJ identity changed: expected `%s`, observed `%s`\n' \
      "$ESCAPED_IDENTITY" "$current" >&2
    return 3
  else
    identity_status=$?
  fi
  [[ $identity_status -eq 1 ]] && return 1
  printf 'contract: AJ identity unavailable for PID %s; refusing signal\n' \
    "$ESCAPED_PID" >&2
  return 2
}

wait_for_escaped_exit() {
  local iteration=0
  local identity_status

  while [[ $iteration -lt $LIFECYCLE_POLL_LIMIT ]]; do
    if observe_escaped_identity; then
      sleep "$LIFECYCLE_POLL_SECONDS"
    else
      identity_status=$?
      [[ $identity_status -eq 1 ]] && return 0
      return "$identity_status"
    fi
    iteration=$((iteration + 1))
  done
  return 1
}

cleanup_escaped() {
  local context=$1
  local identity_status

  [[ -n "$ESCAPED_PID" ]] || return 0
  if observe_escaped_identity; then
    printf 'contract lifecycle %s: KILL escaped pid=%s identity=%s\n' \
      "$context" "$ESCAPED_PID" "$ESCAPED_IDENTITY"
    kill -KILL "$ESCAPED_PID" 2>/dev/null || true
  else
    identity_status=$?
    if [[ $identity_status -eq 1 ]]; then
      ESCAPED_PID=
      ESCAPED_IDENTITY=
      return 0
    fi
    printf 'contract: lifecycle %s refused escaped-PID cleanup (identity status %s)\n' \
      "$context" "$identity_status" >&2
    return "$identity_status"
  fi
  wait_for_escaped_exit || {
    identity_status=$?
    printf 'contract: lifecycle %s escaped PID did not disappear after KILL (identity status %s)\n' \
      "$context" "$identity_status" >&2
    return "$identity_status"
  }
  printf 'contract lifecycle %s: escaped PID disappeared; no reap (not our child)\n' "$context"
  ESCAPED_PID=
  ESCAPED_IDENTITY=
}

start_server() {
  local port_file=$1
  local output_prefix=$2
  local mode=${3:-normal}
  local iteration=0
  local identity_status

  [[ -z "$SERVER_PID" ]] || {
    printf 'contract: lifecycle start requested with PID %s still owned\n' "$SERVER_PID" >&2
    return 1
  }
  SERVER_PID=
  SERVER_IDENTITY=
  if [[ "$mode" == ignore-term ]]; then
    /bin/sh -c "trap '' TERM; exec \"\$1\" tcp-server \"\$2\"" \
      sh "$PROBE" "$port_file" \
      >"${output_prefix}.stdout" 2>"${output_prefix}.stderr" &
  else
    "$PROBE" tcp-server "$port_file" >"${output_prefix}.stdout" 2>"${output_prefix}.stderr" &
  fi
  SERVER_PID=$!
  while [[ $iteration -lt $LIFECYCLE_POLL_LIMIT ]]; do
    if SERVER_IDENTITY=$(process_identity "$SERVER_PID" 2>/dev/null); then
      break
    else
      identity_status=$?
    fi
    if [[ ${IDENTITY_CAPTURE_FAIL_FAST:-0} == 1 && $identity_status -eq 2 ]]; then
      printf 'contract: lifecycle helper identity capture failed immediately for PID %s\n' \
        "$SERVER_PID" >&2
      cleanup_unidentified_server "identity-capture-failure" || return 1
      return 1
    fi
    sleep "$LIFECYCLE_POLL_SECONDS"
    iteration=$((iteration + 1))
  done
  [[ -n "$SERVER_IDENTITY" ]] || {
    printf 'contract: lifecycle helper PID/start identity was not captured for PID %s\n' "$SERVER_PID" >&2
    cleanup_unidentified_server "identity-capture-timeout" || return 1
    return 1
  }
  printf 'contract lifecycle helper: pid=%s start-identity=%s mode=%s\n' \
    "$SERVER_PID" "$SERVER_IDENTITY" "$mode"
}

run_identity_regression() {
  local identity_root="$TMP/lifecycle-identity"
  local port_file="$identity_root/port"
  local output_prefix="$identity_root/server"
  local iteration=0

  mkdir -p "$identity_root"
  (
    SERVER_PID=
    SERVER_IDENTITY=
    trap '
      lifecycle_cleanup_status=0
      cleanup_server "identity-regression-EXIT" || lifecycle_cleanup_status=$?
      if [[ $lifecycle_cleanup_status -ne 0 ]]; then
        exit 1
      fi
    ' EXIT
    IDENTITY_CAPTURE_FORCE_FAIL=1
    IDENTITY_CAPTURE_FAIL_FAST=1
    if start_server "$identity_root/capture-failure-port" \
      "$identity_root/capture-failure"; then
      exit 1
    fi
    [[ -z "$SERVER_PID" && -z "$SERVER_IDENTITY" ]] || exit 1
    IDENTITY_CAPTURE_FORCE_FAIL=0
    IDENTITY_CAPTURE_FAIL_FAST=0

    start_server "$port_file" "$output_prefix"
    while [[ $iteration -lt $LIFECYCLE_POLL_LIMIT ]]; do
      [[ -s "$port_file" ]] && break
      sleep "$LIFECYCLE_POLL_SECONDS"
      iteration=$((iteration + 1))
    done
    [[ -s "$port_file" ]] || exit 1
    [[ "$SERVER_IDENTITY" =~ ^[0-9]+\|[0-9]+\|[0-9]+$ ]] || exit 1
    captured_identity=$SERVER_IDENTITY
    SERVER_IDENTITY="$SERVER_PID|0|0"
    if cleanup_server "identity-mismatch"; then
      exit 1
    fi
    observed_identity=$(process_identity "$SERVER_PID") || exit 1
    [[ "$observed_identity" == "$captured_identity" ]] || exit 1
    printf 'contract lifecycle identity-regression: kernel identity=%s; mismatch refused signal\n' \
      "$captured_identity"
    SERVER_IDENTITY=$captured_identity
    cleanup_server "identity-mismatch-recovery"
  )
}

run_exit_cleanup_regression() {
  local regression_root="$TMP/lifecycle-regression"
  local normal_root="$TMP/lifecycle-normal"
  local normal_port_file="$normal_root/port"
  local port_file="$regression_root/port"
  local normal_iteration=0
  local iteration=0

  mkdir -p "$normal_root"
  mkdir -p "$regression_root"
  run_identity_regression || return 1
  (
    SERVER_PID=
    SERVER_IDENTITY=
    trap '
      lifecycle_cleanup_status=0
      cleanup_server "EXIT-regression" || lifecycle_cleanup_status=$?
      if [[ $lifecycle_cleanup_status -ne 0 ]]; then
        exit 1
      fi
    ' EXIT
    start_server "$normal_port_file" "$normal_root/server"
    while [[ $normal_iteration -lt $LIFECYCLE_POLL_LIMIT ]]; do
      [[ -s "$normal_port_file" ]] && break
      sleep "$LIFECYCLE_POLL_SECONDS"
      normal_iteration=$((normal_iteration + 1))
    done
    [[ -s "$normal_port_file" ]] || exit 1
    cleanup_server "normal-regression" || exit 1
    start_server "$port_file" "$regression_root/server" ignore-term
    while [[ $iteration -lt $LIFECYCLE_POLL_LIMIT ]]; do
      [[ -s "$port_file" ]] && break
      sleep "$LIFECYCLE_POLL_SECONDS"
      iteration=$((iteration + 1))
    done
    [[ -s "$port_file" ]] || exit 1
    owned_server_live || exit 1
    printf 'contract lifecycle EXIT-regression: TERM-ignoring helper pid=%s to exercise bounded KILL fallback\n' \
      "$SERVER_PID"
  )
}

cleanup() {
  local cleanup_status=0
  cleanup_server "EXIT" || cleanup_status=1
  cleanup_escaped "EXIT" || cleanup_status=1
  rm -rf "$TMP" || cleanup_status=1
  if [[ $cleanup_status -ne 0 ]]; then
    printf 'contract: bounded cleanup failed\n' >&2
    exit 1
  fi
}
trap cleanup EXIT

WORK="$TMP/work"
OUTSIDE="$TMP/outside"
WRITE_DIR="$TMP/write"
TMP_ROOT="$TMP/caller-tmp"
mkdir -p "$WORK" "$OUTSIDE" "$WRITE_DIR" "$TMP_ROOT"
chmod 700 "$TMP_ROOT"
TMP_ROOT=$(cd "$TMP_ROOT" && pwd -P)
printf 'inside\n' > "$WORK/inside.txt"
printf 'outside\n' > "$OUTSIDE/outside.txt"
printf 'old\n' > "$WRITE_DIR/file.txt"
printf 'sibling\n' > "$WRITE_DIR/sibling.txt"

# A
[[ "$("$MBOX" --cwd "$WORK" -- /bin/cat inside.txt)" == "inside" ]] || fail A
pass A

# B
expect_failure "$MBOX" --cwd "$WORK" -- /bin/cat "$OUTSIDE/outside.txt"
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
"$MBOX" --cwd "$WORK" -- "$TRUE"
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
expect_status 3 "$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" env TMPDIR
FALLBACK_TMP_TEMPLATE="/tmp/mbox-contract-no-tmp-$$-${RANDOM}-XXXXXX"
expect_failure "$MBOX" --cwd "$WORK" -- /usr/bin/mktemp "$FALLBACK_TMP_TEMPLATE"
FALLBACK_TMP_GLOB=${FALLBACK_TMP_TEMPLATE/XXXXXX/*}
if compgen -G "$FALLBACK_TMP_GLOB" >/dev/null; then
  fail "R wrote fallback temp outside --tmp"
fi
pass R

# R2
scratch_snapshot() {
  find /private/tmp -maxdepth 1 -type d -name '.mbox-*' -print 2>/dev/null | sort
}
SCRATCH_BEFORE=$(scratch_snapshot)
TMPDIR_VALUE=$("$MBOX" --cwd "$WORK" --tmp "$TMP_ROOT" --read "$PROBE" -- "$PROBE" env TMPDIR)
[[ "$TMPDIR_VALUE" == "$TMP_ROOT" ]] || fail "R2 TMPDIR=$TMPDIR_VALUE"
"$MBOX" --cwd "$WORK" --tmp "$TMP_ROOT" -- /bin/sh -c 'test -d "$TMPDIR" && test -w "$TMPDIR" && : > "$TMPDIR/probe"'
[[ -f "$TMP_ROOT/probe" ]] || fail "R2 did not write caller temp"
SCRATCH_AFTER=$(scratch_snapshot)
[[ "$SCRATCH_BEFORE" == "$SCRATCH_AFTER" ]] || fail "R2 created a .mbox scratch directory"
pass R2

# R3
INVALID_TMP_MARKER="$TMP/invalid-tmp-marker"
expect_status 125 "$MBOX" --cwd "$WORK" --tmp "$TMP/missing-tmp" -- /bin/sh -c 'touch "$1"' sh "$INVALID_TMP_MARKER"
[[ ! -e "$INVALID_TMP_MARKER" ]] || fail "R3 missing tmp ran target"
printf 'not a directory\n' > "$TMP/tmp-file"
expect_status 125 "$MBOX" --cwd "$WORK" --tmp "$TMP/tmp-file" -- /bin/sh -c 'touch "$1"' sh "$INVALID_TMP_MARKER"
[[ ! -e "$INVALID_TMP_MARKER" ]] || fail "R3 file tmp ran target"
mkdir "$TMP/wrong-mode-tmp"
chmod 755 "$TMP/wrong-mode-tmp"
expect_status 125 "$MBOX" --cwd "$WORK" --tmp "$TMP/wrong-mode-tmp" -- /bin/sh -c 'touch "$1"' sh "$INVALID_TMP_MARKER"
[[ ! -e "$INVALID_TMP_MARKER" ]] || fail "R3 wrong-mode tmp ran target"
mkdir "$TMP/sticky-mode-tmp"
chmod 1700 "$TMP/sticky-mode-tmp"
expect_status 125 "$MBOX" --cwd "$WORK" --tmp "$TMP/sticky-mode-tmp" -- /bin/sh -c 'touch "$1"' sh "$INVALID_TMP_MARKER"
[[ ! -e "$INVALID_TMP_MARKER" ]] || fail "R3 sticky-bit tmp ran target"
mkdir "$TMP/setgid-mode-tmp"
chmod 2700 "$TMP/setgid-mode-tmp"
expect_status 125 "$MBOX" --cwd "$WORK" --tmp "$TMP/setgid-mode-tmp" -- /bin/sh -c 'touch "$1"' sh "$INVALID_TMP_MARKER"
[[ ! -e "$INVALID_TMP_MARKER" ]] || fail "R3 setgid tmp ran target"
pass R3

# S
ln -s "$PROBE" "$TMP/probe-link"
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$TMP/probe-link" argv ok >"$TMP/symlink"
grep -qx "argv0:$TMP/probe-link" "$TMP/symlink" || fail "S argv0"
grep -qx '0:ok' "$TMP/symlink" || fail S
pass S

# T/U
PORT_FILE="$TMP/port"
start_server "$PORT_FILE" "$TMP/network-server"
for _ in $(seq 1 100); do
  [[ -s "$PORT_FILE" ]] && break
  sleep 0.02
done
[[ -s "$PORT_FILE" ]] || fail "server did not start"
port=$(cat "$PORT_FILE")
expect_failure "$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" tcp-connect "$port"
pass T
"$MBOX" --cwd "$WORK" --read "$PROBE" --network -- "$PROBE" tcp-connect "$port" >"$TMP/network"
cleanup_server "network-normal" || fail "network helper cleanup"
grep -qx ok "$TMP/network" || fail U
pass U

# AF exact HTTPS egress and bypass resistance
CURL=/usr/bin/curl
[[ -x "$CURL" ]] || fail "AF requires /usr/bin/curl for deterministic HTTPS proof"
HTTPS_STATUS=$("$MBOX" --cwd "$WORK" --allow-net EXAMPLE.COM -- "$CURL" \
  --silent --show-error --max-time 8 --output /dev/null --write-out '%{http_code}' \
  https://example.com) || fail "AF allowed HTTPS CONNECT"
[[ "$HTTPS_STATUS" =~ ^[23][0-9][0-9]$ ]] || fail "AF unexpected HTTP status $HTTPS_STATUS"
expect_failure "$MBOX" --cwd "$WORK" --allow-net example.com -- "$CURL" \
  --silent --show-error --max-time 5 --output /dev/null https://www.example.com
expect_failure "$MBOX" --cwd "$WORK" --allow-net example.com -- "$CURL" \
  --silent --show-error --max-time 5 --output /dev/null https://example.com.
expect_failure "$MBOX" --cwd "$WORK" --allow-net example.com -- "$CURL" \
  --silent --show-error --max-time 5 --output /dev/null https://93.184.216.34
expect_failure "$MBOX" --cwd "$WORK" --allow-net example.com -- "$CURL" \
  --silent --show-error --max-time 5 --output /dev/null https://example.com:444
expect_status 125 "$MBOX" --cwd "$WORK" --allow-net '*.example.com' -- "$TRUE"
expect_status 125 "$MBOX" --cwd "$WORK" --allow-net 127.0.0.1 -- "$TRUE"
expect_status 2 "$MBOX" --cwd "$WORK" --network --allow-net example.com -- "$TRUE"
expect_failure "$MBOX" --cwd "$WORK" --allow-net example.com -- /bin/sh -c \
  'unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; \
   /usr/bin/curl --silent --show-error --max-time 5 --output /dev/null https://example.com'
"$MBOX" --cwd "$WORK" --allow-net example.com --set-env NO_PROXY=example.com -- "$CURL" \
  --silent --show-error --max-time 8 --output /dev/null https://example.com
expect_failure "$MBOX" --cwd "$WORK" --read "$PROBE" --allow-net example.com -- \
  "$PROBE" tcp-connect "$port"
expect_failure "$MBOX" --cwd "$WORK" --read "$PROBE" --allow-net example.com -- \
  "$PROBE" tcp-bind
expect_failure "$MBOX" --cwd "$WORK" --allow-net localhost -- "$CURL" \
  --silent --show-error --max-time 5 --output /dev/null https://localhost
expect_failure "$MBOX" --cwd "$WORK" --read "$PROBE" --allow-net example.com -- \
  "$PROBE" raw-dns
expect_failure "$MBOX" --cwd "$WORK" --read "$PROBE" --allow-net example.com -- /bin/sh -c \
  'unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy; \
   "$1" direct-public-ip' sh "$PROBE"
V6_PROXY_PORT_FILE="$TMP/v6-proxy-port"
V6_PROXY_OUTPUT="$TMP/v6-proxy-output"
"$MBOX" --cwd "$WORK" --write "$TMP" --read "$PROBE" --allow-net example.com -- /bin/sh -c \
  'port="${HTTPS_PROXY##*:}"; "$1" proxy-check6 "$port"; printf "%s\n" "$port" >"$2"; sleep 3' \
  sh "$PROBE" "$V6_PROXY_PORT_FILE" >"$V6_PROXY_OUTPUT" 2>&1 &
V6_PROXY_PID=$!
for _ in $(seq 1 100); do
  [[ -s "$V6_PROXY_PORT_FILE" ]] && break
  sleep 0.02
done
[[ -s "$V6_PROXY_PORT_FILE" ]] || fail "AF IPv6 proxy did not publish a live port"
V6_PROXY_PORT=$(cat "$V6_PROXY_PORT_FILE")
"$PROBE" proxy-check6 "$V6_PROXY_PORT" | grep -qx V6-PROXY || \
  fail "AF IPv6 loopback did not use exact proxy"
expect_failure "$PROBE" tcp-bind6 "$V6_PROXY_PORT"
set +e
wait "$V6_PROXY_PID"
V6_PROXY_STATUS=$?
set -e
[[ $V6_PROXY_STATUS -eq 0 ]] || fail "AF IPv6 proxy target status=$V6_PROXY_STATUS"
expect_failure "$PROBE" tcp-connect6 "$V6_PROXY_PORT"
PROXY_ENV=$(
  "$MBOX" --cwd "$WORK" --read "$PROBE" --allow-net example.com -- "$PROBE" env HTTPS_PROXY
)
PROXY_PORT=${PROXY_ENV##*:}
[[ "$PROXY_PORT" =~ ^[0-9]+$ ]] || fail "AF invalid proxy endpoint: $PROXY_ENV"
expect_failure "$PROBE" tcp-connect "$PROXY_PORT"

# Hostile partial headers, RSTs, and overflow are bounded by the proxy's
# worker/header limits. Observe the owning process fd count while the stress
# helper is active, then require a normal CONNECT to recover.
ABUSE_OUTPUT="$TMP/proxy-abuse-output"
ABUSE_PID=
"$MBOX" --cwd "$WORK" --read "$PROBE" --allow-net example.com -- "$PROBE" proxy-abuse \
  >"$ABUSE_OUTPUT" 2>"$TMP/proxy-abuse-stderr" &
ABUSE_PID=$!
ABUSE_MAX_FDS=0
for _ in $(seq 1 180); do
  if ! kill -0 "$ABUSE_PID" 2>/dev/null; then
    break
  fi
  if count=$("$PROBE" process-fd-count "$ABUSE_PID" 2>/dev/null); then
    [[ "$count" =~ ^[0-9]+$ ]] || fail "AF invalid proxy fd count: $count"
    (( count > ABUSE_MAX_FDS )) && ABUSE_MAX_FDS=$count
  fi
  sleep 0.02
done
set +e
wait "$ABUSE_PID"
ABUSE_STATUS=$?
set -e
[[ $ABUSE_STATUS -eq 0 ]] || fail "AF proxy abuse recovery status=$ABUSE_STATUS"
grep -qx ABUSE-RECOVERED "$ABUSE_OUTPUT" || fail "AF proxy abuse did not recover"
[[ $ABUSE_MAX_FDS -le 256 ]] || fail "AF proxy fd count unbounded: $ABUSE_MAX_FDS"
pass AF

# AF-SNI proves that CONNECT authority and the TLS endpoint identity are one
# policy decision. curl's connect-to form keeps avatars' SNI while making the
# proxy CONNECT to raw; the latter is allowed, but the former must be refused.
RAW_SNI_STATUS=$(
  "$MBOX" --cwd "$WORK" --allow-net raw.githubusercontent.com -- "$CURL" \
    --silent --show-error --max-time 8 --output /dev/null --write-out '%{http_code}' \
    --connect-to raw.githubusercontent.com:443:raw.githubusercontent.com:443 \
    https://raw.githubusercontent.com/openai/codex/main/README.md
) || fail "AF-SNI exact TLS request"
[[ "$RAW_SNI_STATUS" =~ ^[23][0-9][0-9]$ ]] || fail "AF-SNI unexpected HTTP status $RAW_SNI_STATUS"
expect_failure "$MBOX" --cwd "$WORK" --allow-net raw.githubusercontent.com -- "$CURL" \
  --silent --show-error --max-time 5 --output /dev/null \
  --connect-to avatars.githubusercontent.com:443:raw.githubusercontent.com:443 \
  https://avatars.githubusercontent.com/
pass AF-SNI

# AG active tunnel and target-group cleanup on parent cancellation
HOLD_PID=
HOLD_CHILD_PID_FILE="$TMP/hold-child.pid"
HOLD_OUTPUT="$TMP/hold-output"
"$MBOX" --cwd "$WORK" --write "$TMP" --read "$PROBE" --allow-net example.com -- \
  /bin/sh -c '"$1" proxy-hold example.com 30 >"$2" 2>&1 & echo $! >"$3"; wait' \
  sh "$PROBE" "$HOLD_OUTPUT" "$HOLD_CHILD_PID_FILE" &
HOLD_PID=$!
for _ in $(seq 1 200); do
  [[ -s "$HOLD_OUTPUT" ]] && break
  sleep 0.02
done
grep -qx READY "$HOLD_OUTPUT" || fail "AG proxy tunnel did not become active"
HOLD_CHILD_PID=$(cat "$HOLD_CHILD_PID_FILE")
kill -TERM "$HOLD_PID"
set +e
wait "$HOLD_PID"
hold_status=$?
set -e
[[ $hold_status -eq 143 ]] || fail "AG mbox signal status=$hold_status"
if kill -0 "$HOLD_CHILD_PID" 2>/dev/null; then
  fail "AG proxy tunnel descendant survived immediate cleanup"
fi
sleep "$LIFECYCLE_POST_WATCH_SECONDS"
if kill -0 "$HOLD_CHILD_PID" 2>/dev/null; then
  fail "AG proxy tunnel descendant survived delayed cleanup"
fi
HOLD_PID=
pass AG

# AI normal leader exit must still clean a background descendant before the
# waitable leader is reaped; SIGINT must use the same owned-group path.
LEADER_CHILD_PID_FILE="$TMP/leader-child.pid"
"$MBOX" --cwd "$WORK" --write "$TMP" --allow-net example.com -- /bin/sh -c \
  'sleep 30 & echo $! >"$1"; exit 0' sh "$LEADER_CHILD_PID_FILE"
[[ -s "$LEADER_CHILD_PID_FILE" ]] || fail "AI leader child pid missing"
LEADER_CHILD_PID=$(cat "$LEADER_CHILD_PID_FILE")
if kill -0 "$LEADER_CHILD_PID" 2>/dev/null; then
  fail "AI normal leader descendant survived immediate cleanup"
fi
sleep "$LIFECYCLE_POST_WATCH_SECONDS"
if kill -0 "$LEADER_CHILD_PID" 2>/dev/null; then
  fail "AI normal leader descendant survived delayed cleanup"
fi

INT_HOLD_OUTPUT="$TMP/int-hold-output"
"$MBOX" --cwd "$WORK" --write "$TMP" --read "$PROBE" --allow-net example.com -- \
  "$PROBE" proxy-hold example.com 30 >"$INT_HOLD_OUTPUT" 2>&1 &
INT_HOLD_PID=$!
for _ in $(seq 1 200); do
  [[ -s "$INT_HOLD_OUTPUT" ]] && break
  sleep 0.02
done
grep -qx READY "$INT_HOLD_OUTPUT" || fail "AI SIGINT tunnel did not become active"
kill -INT "$INT_HOLD_PID"
set +e
wait "$INT_HOLD_PID"
INT_HOLD_STATUS=$?
set -e
[[ $INT_HOLD_STATUS -eq 130 ]] || fail "AI SIGINT status=$INT_HOLD_STATUS"
if kill -0 "$INT_HOLD_PID" 2>/dev/null; then
  fail "AI SIGINT target survived immediate cleanup"
fi
sleep "$LIFECYCLE_POST_WATCH_SECONDS"
if kill -0 "$INT_HOLD_PID" 2>/dev/null; then
  fail "AI SIGINT target survived delayed cleanup"
fi
pass AI

# AJ records the macOS lifecycle boundary: a target can call setsid(2) and
# double-fork out of the initial process group. mbox must not claim ownership
# of that escaped process without a kernel-owned descendant primitive.
SETSID_PID_FILE="$TMP/setsid-escape.pid"
SETSID_OUTPUT="$TMP/setsid-escape-output"
"$MBOX" --cwd "$WORK" --write "$TMP" --read "$PROBE" --allow-net example.com -- \
  "$PROBE" setsid-escape "$SETSID_PID_FILE" >"$SETSID_OUTPUT" 2>&1
grep -qx SETSID-ESCAPE-UNOWNED "$SETSID_OUTPUT" || fail "AJ setsid escape was not recorded"
[[ -s "$SETSID_PID_FILE" ]] || fail "AJ setsid escape pid missing"
SETSID_IDENTITY=$(cat "$SETSID_PID_FILE")
[[ "$SETSID_IDENTITY" =~ ^[0-9]+\|[0-9]+\|[0-9]+$ ]] || \
  fail "AJ invalid escaped process record: $SETSID_IDENTITY"
SETSID_PID=${SETSID_IDENTITY%%|*}
ESCAPED_PID=$SETSID_PID
# Keep the probe's kernel tuple in the EXIT-trap state before the fresh host
# observation. If a later AJ assertion aborts, cleanup can still refuse any
# PID reuse safely instead of falling back to a bare PID signal.
ESCAPED_IDENTITY=$SETSID_IDENTITY
OBSERVED_ESCAPED_IDENTITY=$(process_identity "$ESCAPED_PID") || \
  fail "AJ escaped process identity was unavailable"
[[ "$OBSERVED_ESCAPED_IDENTITY" == "$ESCAPED_IDENTITY" ]] || \
  fail "AJ escaped process identity changed before cleanup"
ESCAPED_IDENTITY=$OBSERVED_ESCAPED_IDENTITY
observe_escaped_identity || fail "AJ escaped process identity changed before cleanup"
cleanup_escaped "AJ" || fail "AJ escaped process cleanup failed"
[[ -z "$ESCAPED_PID" && -z "$ESCAPED_IDENTITY" ]] || \
  fail "AJ escaped process cleanup state was not cleared"
pass AJ

# V
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" unix-socketpair | grep -qx OK
pass V

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
TOOL_DIR="$TMP/tool"
mkdir "$TOOL_DIR"
cp "$PROBE" "$TOOL_DIR/probe"
SIBLING_SECRET="$TOOL_DIR/sibling-secret"
printf 'parent-secret\n' > "$SIBLING_SECRET"
expect_failure "$MBOX" --cwd "$WORK" -- "$TOOL_DIR/probe" read-file "$SIBLING_SECRET"
[[ "$("$MBOX" --cwd "$WORK" --read "$SIBLING_SECRET" -- "$TOOL_DIR/probe" read-file "$SIBLING_SECRET")" == "parent-secret" ]] || fail AA
pass AA

# AB
CANON_PARENT="$TMP/canonical-parent"
CANON_NESTED="$CANON_PARENT/nested"
mkdir -p "$CANON_NESTED"
CANON_TARGET="$CANON_NESTED/target.txt"
CANON_SIBLING="$CANON_NESTED/sibling.txt"
CANON_PARENT_FILE="$CANON_PARENT/parent.txt"
printf 'canonical-target\n' > "$CANON_TARGET"
printf 'sibling-secret\n' > "$CANON_SIBLING"
printf 'parent-secret\n' > "$CANON_PARENT_FILE"
[[ "$("$MBOX" --cwd "$WORK" --read "$CANON_TARGET" -- "$PROBE" canonicalize-read "$CANON_TARGET")" == "canonical-target" ]] || fail AB
expect_failure "$MBOX" --cwd "$WORK" --read "$CANON_TARGET" -- "$PROBE" canonicalize-read "$CANON_SIBLING"
expect_failure "$MBOX" --cwd "$WORK" --read "$CANON_TARGET" -- "$PROBE" canonicalize-read "$CANON_PARENT_FILE"
pass AB

# AC
"$MBOX" --cwd "$WORK" --read "$PROBE" -- "$PROBE" tty-injection | grep -qx EPERM
pass AC

# AD
EXEC_DIR="$TMP/executable-write-root"
mkdir "$EXEC_DIR"
EXECUTABLE="$EXEC_DIR/probe"
SIBLING="$EXEC_DIR/sibling"
REPLACEMENT="$EXEC_DIR/replacement"
cp "$PROBE" "$EXECUTABLE"
printf 'sibling\n' > "$SIBLING"
"$MBOX" --cwd "$WORK" --write "$EXEC_DIR" -- "$EXECUTABLE" remove-file "$SIBLING"
[[ ! -e "$SIBLING" ]] || fail "AD sibling remained"
printf 'sibling\n' > "$SIBLING"
expect_failure "$MBOX" --cwd "$WORK" --write "$EXEC_DIR" -- "$EXECUTABLE" remove-file "$EXECUTABLE"
cp "$PROBE" "$REPLACEMENT"
expect_failure "$MBOX" --cwd "$WORK" --write "$EXEC_DIR" -- \
  "$EXECUTABLE" rename-file "$REPLACEMENT" "$EXECUTABLE"
[[ -e "$REPLACEMENT" ]] || fail "AD replacement was consumed"
[[ -x "$EXECUTABLE" ]] || fail "AD executable was removed"
cmp "$PROBE" "$EXECUTABLE" >/dev/null || fail "AD executable changed"
pass AD

# AH deny-write subtraction for nonexistent .git, directory, file pointer,
# removal, rename, replacement, and allowed siblings.
GIT_ROOT="$TMP/git-work"
mkdir "$GIT_ROOT"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  /bin/sh -c 'mkdir "$1/.git"; touch "$1/.git/config"' sh "$GIT_ROOT"
[[ ! -e "$GIT_ROOT/.git" ]] || fail "AH nonexistent .git was created"
mkdir "$GIT_ROOT/.git"
printf 'git-config\n' > "$GIT_ROOT/.git/config"
printf 'replacement\n' > "$GIT_ROOT/replacement"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  /bin/sh -c 'printf changed > "$1/.git/config"' sh "$GIT_ROOT"
[[ $(cat "$GIT_ROOT/.git/config") == git-config ]] || fail "AH protected config changed"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  "$PROBE" remove-file "$GIT_ROOT/.git/config"
[[ -f "$GIT_ROOT/.git/config" ]] || fail "AH protected config removed"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  "$PROBE" rename-file "$GIT_ROOT/replacement" "$GIT_ROOT/.git/config"
[[ -f "$GIT_ROOT/replacement" ]] || fail "AH replacement source consumed"
[[ $(cat "$GIT_ROOT/.git/config") == git-config ]] || fail "AH protected config replaced"
printf sibling > "$GIT_ROOT/sibling"
"$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  /bin/sh -c 'printf sibling-ok > "$1/sibling"' sh "$GIT_ROOT"
[[ $(cat "$GIT_ROOT/sibling") == sibling-ok ]] || fail "AH allowed sibling write failed"
GIT_POINTER="$GIT_ROOT/git-pointer"
printf 'ref: refs/heads/main\n' > "$GIT_POINTER"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_POINTER" -- \
  /bin/sh -c 'printf changed > "$1"' sh "$GIT_POINTER"
[[ $(cat "$GIT_POINTER") == 'ref: refs/heads/main' ]] || fail "AH file pointer changed"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  "$PROBE" remove-dir "$GIT_ROOT/.git"
[[ -d "$GIT_ROOT/.git" ]] || fail "AH protected directory removed"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  "$PROBE" rename-file "$GIT_ROOT/.git" "$GIT_ROOT/git-renamed"
[[ -d "$GIT_ROOT/.git" ]] || fail "AH protected directory renamed"
HARDLINK_ROOT="$TMP/hardlinks"
mkdir "$HARDLINK_ROOT"
HARDLINK_FILE="$HARDLINK_ROOT/protected"
HARDLINK_FILE_ALIAS="$HARDLINK_ROOT/protected-alias"
printf protected >"$HARDLINK_FILE"
ln "$HARDLINK_FILE" "$HARDLINK_FILE_ALIAS"
expect_status 125 "$MBOX" --cwd "$WORK" --write "$HARDLINK_ROOT" \
  --deny-write "$HARDLINK_FILE" -- "$TRUE"
HARDLINK_EXEC_ALIAS="$HARDLINK_ROOT/executable-alias"
ln "$PROBE" "$HARDLINK_EXEC_ALIAS"
expect_status 125 "$MBOX" --cwd "$WORK" --write "$HARDLINK_ROOT" -- \
  "$HARDLINK_EXEC_ALIAS" streams
HARDLINK_IN_SANDBOX_ALIAS="$GIT_ROOT/config-alias"
expect_failure "$MBOX" --cwd "$WORK" --write "$GIT_ROOT" --deny-write "$GIT_ROOT/.git" -- \
  /bin/sh -c 'ln "$1/.git/config" "$1/config-alias" && printf changed >"$1/config-alias"' \
  sh "$GIT_ROOT"
[[ ! -e "$HARDLINK_IN_SANDBOX_ALIAS" ]] || fail "AH in-sandbox hardlink alias created"
[[ $(cat "$GIT_ROOT/.git/config") == git-config ]] || fail "AH hardlink mutated protected file"
pass AH

# AE
run_exit_cleanup_regression || fail AE
pass AE

printf 'contract A-AJ + AE: PASS (Darwin)\n'
