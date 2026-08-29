#!/usr/bin/env -S -i PATH=/usr/bin:/bin HOME=/Users/ax LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 /bin/bash
# Shared trusted-tool contract for the Darwin release protocol.
#
# This file is sourced only by the release verifier and its nested static and
# native contract gates.  It deliberately never resolves a security-critical
# tool through the caller's PATH.  The caller may provide the exact toolchain
# paths and digests through MBOX_RELEASE_* variables; otherwise the fixed
# Homebrew rustup entry points are used only to discover the actual toolchain
# binaries, which are then pinned and revalidated.

MBOX_RELEASE_SYSTEM_PATH=/usr/bin:/bin:/usr/sbin:/sbin
MBOX_RELEASE_BASH_PATH=/bin/bash
MBOX_RELEASE_AWK_PATH=/usr/bin/awk
MBOX_RELEASE_CHMOD_PATH=/bin/chmod
MBOX_RELEASE_CMP_PATH=/usr/bin/cmp
MBOX_RELEASE_CP_PATH=/bin/cp
MBOX_RELEASE_DIRNAME_PATH=/usr/bin/dirname
MBOX_RELEASE_FIND_PATH=/usr/bin/find
MBOX_RELEASE_GREP_PATH=/usr/bin/grep
MBOX_RELEASE_HEAD_PATH=/usr/bin/head
MBOX_RELEASE_ID_PATH=/usr/bin/id

MBOX_RELEASE_GETCONF_PATH=/usr/bin/getconf
MBOX_RELEASE_LN_PATH=/bin/ln
MBOX_RELEASE_MKDIR_PATH=/bin/mkdir
MBOX_RELEASE_MKTEMP_PATH=/usr/bin/mktemp
MBOX_RELEASE_MV_PATH=/bin/mv
MBOX_RELEASE_PWD_PATH=/bin/pwd
MBOX_RELEASE_READLINK_PATH=/usr/bin/readlink
MBOX_RELEASE_REALPATH_PATH=/bin/realpath
MBOX_RELEASE_RM_PATH=/bin/rm
MBOX_RELEASE_SED_PATH=/usr/bin/sed
MBOX_RELEASE_SHA256SUM_PATH=/sbin/sha256sum
MBOX_RELEASE_SHASUM_PATH=/usr/bin/shasum
MBOX_RELEASE_SORT_PATH=/usr/bin/sort
MBOX_RELEASE_STAT_PATH=/usr/bin/stat
MBOX_RELEASE_UNAME_PATH=/usr/bin/uname
MBOX_RELEASE_XCRUN_PATH=/usr/bin/xcrun
MBOX_RELEASE_CLANG_PATH=/usr/bin/clang
MBOX_RELEASE_ENV_PATH=/usr/bin/env

# A release-critical child must start Bash from an empty environment. The
# caller passes only protocol-owned values below; startup controls such as
# BASH_ENV, ENV, SHELLOPTS, BASHOPTS, CDPATH, GLOBIGNORE, and BASH_XTRACEFD
# never cross this boundary. This is intentionally an allowlist rather than
# an unset loop: Bash reads BASH_ENV before the child body can unset it.
mbox_release_run_script() {
  local script=$1
  shift
  [[ "$script" == /* && "$script" != *$'\n'* && "$script" != *$'\t'* ]] ||
    mbox_release_fail "nested script path is not a canonical absolute path"
  [[ -f "$script" && ! -L "$script" && -x "$script" ]] ||
    mbox_release_fail "nested script is missing, symlinked, or not executable: $script"
  local canonical
  canonical=$($MBOX_RELEASE_REALPATH_PATH "$script") ||
    mbox_release_fail "could not canonicalize nested script: $script"
  [[ "$canonical" == "$script" ]] ||
    mbox_release_fail "nested script is not canonical: $script"

  local -a sanitized_env
  sanitized_env=(
    "PATH=$MBOX_RELEASE_SYSTEM_PATH"
    "HOME=/Users/ax"
    "LC_ALL=C"
    "MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1"
  )
  local name
  for name in \
    MBOX_RELEASE_PROVENANCE \
    MBOX_RELEASE_SYSTEM_PATH MBOX_RELEASE_BASH_PATH \
    MBOX_RELEASE_AWK_PATH MBOX_RELEASE_CHMOD_PATH MBOX_RELEASE_CMP_PATH \
    MBOX_RELEASE_CP_PATH MBOX_RELEASE_DIRNAME_PATH MBOX_RELEASE_ENV_PATH \
    MBOX_RELEASE_FIND_PATH MBOX_RELEASE_GREP_PATH MBOX_RELEASE_HEAD_PATH \
    MBOX_RELEASE_ID_PATH MBOX_RELEASE_LN_PATH MBOX_RELEASE_MKDIR_PATH \
    MBOX_RELEASE_MKTEMP_PATH MBOX_RELEASE_MV_PATH MBOX_RELEASE_PWD_PATH \
    MBOX_RELEASE_READLINK_PATH MBOX_RELEASE_REALPATH_PATH MBOX_RELEASE_RM_PATH \
    MBOX_RELEASE_SED_PATH MBOX_RELEASE_SHA256SUM_PATH MBOX_RELEASE_SHASUM_PATH \
    MBOX_RELEASE_SORT_PATH MBOX_RELEASE_STAT_PATH MBOX_RELEASE_UNAME_PATH \
    MBOX_RELEASE_XCRUN_PATH MBOX_RELEASE_CLANG_PATH \
    MBOX_RELEASE_CARGO_PATH MBOX_RELEASE_CARGO_SHA256 MBOX_RELEASE_CARGO_VERSION \
    MBOX_RELEASE_RUSTC_PATH MBOX_RELEASE_RUSTC_SHA256 MBOX_RELEASE_RUSTC_VERSION \
    MBOX_RELEASE_RUSTFMT_PATH MBOX_RELEASE_RUSTFMT_SHA256 \
    MBOX_RELEASE_CLIPPY_DRIVER_PATH MBOX_RELEASE_CLIPPY_DRIVER_SHA256 \
    MBOX_RELEASE_LINKER_PATH MBOX_RELEASE_LINKER_SHA256 \
    MBOX_RELEASE_XCRUN_SHA256 MBOX_RELEASE_SDK_PATH \
    MBOX_RELEASE_TOOLCHAIN_NAME MBOX_RELEASE_TOOLCHAIN_BIN \
    MBOX_RELEASE_PROVENANCE_CARGO_SHA256 \
    MBOX_RELEASE_PROVENANCE_RUSTC_SHA256 \
    MBOX_RELEASE_PROVENANCE_RUSTFMT_SHA256 \
    MBOX_RELEASE_PROVENANCE_CLIPPY_DRIVER_SHA256 \
    MBOX_RELEASE_PROVENANCE_LINKER_SHA256 \
    MBOX PROBE BUILD_MBOX RUSTC RUSTC_LINKER SDKROOT; do
    if [[ ${!name+x} ]]; then
      sanitized_env+=("$name=${!name}")
    fi
  done

  "$MBOX_RELEASE_ENV_PATH" -i "${sanitized_env[@]}" \
    "$MBOX_RELEASE_BASH_PATH" "$script" "$@"
}

# These are fixed-system utility digests for the supported local Darwin
# protocol.  The root-ownership and non-writable-ancestor checks below remain
# the primary gate; the digest makes a changed utility fail closed before it
# can be used for a provenance decision.  Same-account host mutation remains
# outside this protocol's proof boundary.
MBOX_RELEASE_SHA256SUM_SHA256=881f3812ac7be70d99bf635e5322b63f565af66f502be3b464036fef8f927300
MBOX_RELEASE_SHASUM_SHA256=0812595f981a26f813d98dc380af14d4af427626c9339eda29eb849ae13de1e3

mbox_release_fail() {
  printf 'macos release-tools: FAIL: %s\n' "$*" >&2
  return 1
}

mbox_release_root_tool() {
  local path=$1 owner mode numeric parent
  [[ "$path" == /usr/bin/* || "$path" == /bin/* ||
    "$path" == /usr/sbin/* || "$path" == /sbin/* ]] ||
    mbox_release_fail "system tool is outside the fixed macOS roots: $path"
  [[ -f "$path" && ! -L "$path" && -x "$path" ]] ||
    mbox_release_fail "fixed system tool is missing, symlinked, or not executable: $path"
  owner=$($MBOX_RELEASE_STAT_PATH -f '%u' "$path") ||
    mbox_release_fail "could not inspect fixed system tool owner: $path"
  [[ "$owner" == 0 ]] || mbox_release_fail "fixed system tool is not root-owned: $path"
  mode=$($MBOX_RELEASE_STAT_PATH -f '%Lp' "$path") ||
    mbox_release_fail "could not inspect fixed system tool mode: $path"
  [[ "$mode" =~ ^[0-7]{3}$ ]] || mbox_release_fail "fixed system tool mode is invalid: $path"
  numeric=$((8#$mode))
  (( (numeric & 0022) == 0 )) ||
    mbox_release_fail "fixed system tool is writable by group or other: $path"
  parent=$($MBOX_RELEASE_DIRNAME_PATH "$path") ||
    mbox_release_fail "could not inspect fixed system tool parent: $path"
  while :; do
    owner=$($MBOX_RELEASE_STAT_PATH -f '%u' "$parent") ||
      mbox_release_fail "could not inspect fixed system tool ancestor: $parent"
    [[ "$owner" == 0 && -d "$parent" ]] ||
      mbox_release_fail "fixed system tool ancestor is not root-owned: $parent"
    mode=$($MBOX_RELEASE_STAT_PATH -f '%Lp' "$parent") ||
      mbox_release_fail "could not inspect fixed system tool ancestor mode: $parent"
    [[ "$mode" =~ ^[0-7]{3}$ ]] || mbox_release_fail "fixed system tool ancestor mode is invalid: $parent"
    numeric=$((8#$mode))
    (( (numeric & 0022) == 0 )) ||
      mbox_release_fail "fixed system tool ancestor is writable by group or other: $parent"
    [[ "$parent" == / ]] && break
    parent=$($MBOX_RELEASE_DIRNAME_PATH "$parent") ||
      mbox_release_fail "could not walk fixed system tool ancestors"
  done
}

mbox_release_tool_path() {
  local path=$1
  [[ "$path" == /* && "$path" != *$'\n'* && "$path" != *$'\t'* &&
    "$path" != *' '* ]] || mbox_release_fail "tool path is not a canonical absolute path"
  [[ -f "$path" && ! -L "$path" && -x "$path" ]] ||
    mbox_release_fail "tool path is missing, symlinked, or not executable: $path"
  local canonical
  canonical=$($MBOX_RELEASE_REALPATH_PATH "$path") ||
    mbox_release_fail "could not canonicalize tool path: $path"
  [[ "$canonical" == "$path" ]] || mbox_release_fail "tool path is not canonical: $path"
  local mode
  mode=$($MBOX_RELEASE_STAT_PATH -f '%Lp' "$path") ||
    mbox_release_fail "could not inspect tool mode: $path"
  [[ "$mode" =~ ^[0-7]{3}$ ]] || mbox_release_fail "tool mode is invalid: $path"
  (( (8#$mode & 0022) == 0 )) || mbox_release_fail "tool is writable by group or other: $path"
}

mbox_release_hash_file() {
  local path=$1
  mbox_release_root_tool "$MBOX_RELEASE_SHA256SUM_PATH" || return
  mbox_release_root_tool "$MBOX_RELEASE_SHASUM_PATH" || return
  local verifier_digest shasum_digest
  verifier_digest=$($MBOX_RELEASE_SHA256SUM_PATH "$MBOX_RELEASE_SHA256SUM_PATH" | $MBOX_RELEASE_AWK_PATH '{print $1}') || return
  [[ "$verifier_digest" == "$MBOX_RELEASE_SHA256SUM_SHA256" ]] ||
    mbox_release_fail "sha256 verifier digest changed" || return
  shasum_digest=$($MBOX_RELEASE_SHA256SUM_PATH "$MBOX_RELEASE_SHASUM_PATH" | $MBOX_RELEASE_AWK_PATH '{print $1}') || return
  [[ "$shasum_digest" == "$MBOX_RELEASE_SHASUM_SHA256" ]] ||
    mbox_release_fail "shasum digest changed" || return
  "$MBOX_RELEASE_SHASUM_PATH" -a 256 -- "$path" | "$MBOX_RELEASE_AWK_PATH" '{print $1}'
}

mbox_release_recheck_tool() {
  local name=$1 path=$2 expected=$3 digest provenance_expected=
  case "$name" in
    cargo) provenance_expected=${MBOX_RELEASE_PROVENANCE_CARGO_SHA256-} ;;
    rustc) provenance_expected=${MBOX_RELEASE_PROVENANCE_RUSTC_SHA256-} ;;
    rustfmt) provenance_expected=${MBOX_RELEASE_PROVENANCE_RUSTFMT_SHA256-} ;;
    clippy-driver) provenance_expected=${MBOX_RELEASE_PROVENANCE_CLIPPY_DRIVER_SHA256-} ;;
    linker) provenance_expected=${MBOX_RELEASE_PROVENANCE_LINKER_SHA256-} ;;
  esac
  [[ -z "$provenance_expected" || "$expected" == "$provenance_expected" ]] ||
    mbox_release_fail "$name digest is not the recorded release digest"
  mbox_release_tool_path "$path" || return
  digest=$(mbox_release_hash_file "$path") || return
  [[ "$digest" == "$expected" ]] ||
    mbox_release_fail "$name digest changed before use: $path"
  [[ -z "$provenance_expected" || "$digest" == "$provenance_expected" ]] ||
    mbox_release_fail "$name digest changed from the recorded release digest: $path"
}

mbox_release_discover_toolchain() {
  local rustup_path rustup_canonical cargo_path rustc_path toolchain_dir candidate
  if [[ "${MBOX_RELEASE_PROVENANCE:-0}" == 1 ]]; then
    : "${MBOX_RELEASE_CARGO_PATH:?MBOX_RELEASE_CARGO_PATH is required in provenance mode}"
    : "${MBOX_RELEASE_RUSTC_PATH:?MBOX_RELEASE_RUSTC_PATH is required in provenance mode}"
    : "${MBOX_RELEASE_RUSTFMT_PATH:?MBOX_RELEASE_RUSTFMT_PATH is required in provenance mode}"
    : "${MBOX_RELEASE_CLIPPY_DRIVER_PATH:?MBOX_RELEASE_CLIPPY_DRIVER_PATH is required in provenance mode}"
    : "${MBOX_RELEASE_CARGO_SHA256:?MBOX_RELEASE_CARGO_SHA256 is required in provenance mode}"
    : "${MBOX_RELEASE_RUSTC_SHA256:?MBOX_RELEASE_RUSTC_SHA256 is required in provenance mode}"
    : "${MBOX_RELEASE_RUSTFMT_SHA256:?MBOX_RELEASE_RUSTFMT_SHA256 is required in provenance mode}"
    : "${MBOX_RELEASE_CLIPPY_DRIVER_SHA256:?MBOX_RELEASE_CLIPPY_DRIVER_SHA256 is required in provenance mode}"
  else
    rustup_path=
    for candidate in /opt/homebrew/bin/rustup /usr/local/bin/rustup; do
      if [[ -x "$candidate" ]]; then
        rustup_path=$candidate
        break
      fi
    done
    [[ -n "$rustup_path" ]] || mbox_release_fail "fixed rustup entry point is unavailable"
    rustup_canonical=$($MBOX_RELEASE_REALPATH_PATH "$rustup_path") ||
      mbox_release_fail "could not canonicalize fixed rustup entry point"
    mbox_release_tool_path "$rustup_canonical" || return
    cargo_path=$($MBOX_RELEASE_ENV_PATH -i HOME=/Users/ax RUSTUP_HOME=/Users/ax/.rustup \
      LC_ALL=C PATH="$MBOX_RELEASE_SYSTEM_PATH" "$rustup_canonical" which cargo) ||
      mbox_release_fail "rustup could not identify the actual cargo binary"
    rustc_path=$($MBOX_RELEASE_ENV_PATH -i HOME=/Users/ax RUSTUP_HOME=/Users/ax/.rustup \
      LC_ALL=C PATH="$MBOX_RELEASE_SYSTEM_PATH" "$rustup_canonical" which rustc) ||
      mbox_release_fail "rustup could not identify the actual rustc binary"
    MBOX_RELEASE_CARGO_PATH=$cargo_path
    MBOX_RELEASE_RUSTC_PATH=$rustc_path
    toolchain_dir=$($MBOX_RELEASE_DIRNAME_PATH "$cargo_path") || return
    [[ "$toolchain_dir" == "$($MBOX_RELEASE_DIRNAME_PATH "$rustc_path")" ]] ||
      mbox_release_fail "cargo and rustc are from different toolchains"
    MBOX_RELEASE_RUSTFMT_PATH="$toolchain_dir/rustfmt"
    MBOX_RELEASE_CLIPPY_DRIVER_PATH="$toolchain_dir/clippy-driver"
    MBOX_RELEASE_CARGO_SHA256=$(mbox_release_hash_file "$MBOX_RELEASE_CARGO_PATH") || return
    MBOX_RELEASE_RUSTC_SHA256=$(mbox_release_hash_file "$MBOX_RELEASE_RUSTC_PATH") || return
    MBOX_RELEASE_RUSTFMT_SHA256=$(mbox_release_hash_file "$MBOX_RELEASE_RUSTFMT_PATH") || return
    MBOX_RELEASE_CLIPPY_DRIVER_SHA256=$(mbox_release_hash_file "$MBOX_RELEASE_CLIPPY_DRIVER_PATH") || return
  fi

  mbox_release_tool_path "$MBOX_RELEASE_CARGO_PATH" || return
  mbox_release_tool_path "$MBOX_RELEASE_RUSTC_PATH" || return
  mbox_release_tool_path "$MBOX_RELEASE_RUSTFMT_PATH" || return
  mbox_release_tool_path "$MBOX_RELEASE_CLIPPY_DRIVER_PATH" || return
  mbox_release_recheck_tool cargo "$MBOX_RELEASE_CARGO_PATH" "$MBOX_RELEASE_CARGO_SHA256" || return
  mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$MBOX_RELEASE_RUSTC_SHA256" || return
  mbox_release_recheck_tool rustfmt "$MBOX_RELEASE_RUSTFMT_PATH" "$MBOX_RELEASE_RUSTFMT_SHA256" || return
  mbox_release_recheck_tool clippy-driver "$MBOX_RELEASE_CLIPPY_DRIVER_PATH" "$MBOX_RELEASE_CLIPPY_DRIVER_SHA256" || return

  MBOX_RELEASE_TOOLCHAIN_BIN=$($MBOX_RELEASE_DIRNAME_PATH "$MBOX_RELEASE_CARGO_PATH") || return
  MBOX_RELEASE_TOOLCHAIN_NAME=$($MBOX_RELEASE_ENV_PATH -i HOME=/Users/ax RUSTUP_HOME=/Users/ax/.rustup \
    LC_ALL=C PATH="$MBOX_RELEASE_SYSTEM_PATH" "$MBOX_RELEASE_RUSTC_PATH" --version | \
    $MBOX_RELEASE_AWK_PATH '{print $2}') || return
  MBOX_RELEASE_CARGO_VERSION=$("$MBOX_RELEASE_CARGO_PATH" --version) || return
  MBOX_RELEASE_RUSTC_VERSION=$("$MBOX_RELEASE_RUSTC_PATH" --version) || return
  local cargo_version_re='^cargo [0-9]+\.[0-9]+\.[0-9]+ \([^)]*\)$'
  local rustc_version_re='^rustc [0-9]+\.[0-9]+\.[0-9]+ \([^)]*\)$'
  [[ "$MBOX_RELEASE_CARGO_VERSION" =~ $cargo_version_re ]] ||
    mbox_release_fail "unexpected cargo version output"
  [[ "$MBOX_RELEASE_RUSTC_VERSION" =~ $rustc_version_re ]] ||
    mbox_release_fail "unexpected rustc version output"
  export MBOX_RELEASE_CARGO_PATH MBOX_RELEASE_RUSTC_PATH
  export MBOX_RELEASE_RUSTFMT_PATH MBOX_RELEASE_CLIPPY_DRIVER_PATH
  export MBOX_RELEASE_CARGO_SHA256 MBOX_RELEASE_RUSTC_SHA256
  export MBOX_RELEASE_RUSTFMT_SHA256 MBOX_RELEASE_CLIPPY_DRIVER_SHA256
  export MBOX_RELEASE_TOOLCHAIN_BIN MBOX_RELEASE_TOOLCHAIN_NAME
  export MBOX_RELEASE_CARGO_VERSION MBOX_RELEASE_RUSTC_VERSION
  export PATH="$MBOX_RELEASE_TOOLCHAIN_BIN:$MBOX_RELEASE_SYSTEM_PATH"
}

mbox_release_run_cargo() {
  mbox_release_recheck_tool cargo "$MBOX_RELEASE_CARGO_PATH" "$MBOX_RELEASE_CARGO_SHA256" || return
  "$MBOX_RELEASE_CARGO_PATH" "$@"
}

mbox_release_run_rustc() {
  mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$MBOX_RELEASE_RUSTC_SHA256" || return
  "$MBOX_RELEASE_RUSTC_PATH" "$@"
}

mbox_release_run_rustfmt() {
  mbox_release_recheck_tool rustfmt "$MBOX_RELEASE_RUSTFMT_PATH" "$MBOX_RELEASE_RUSTFMT_SHA256" || return
  "$MBOX_RELEASE_RUSTFMT_PATH" "$@"
}

mbox_release_run_clippy_driver() {
  mbox_release_recheck_tool clippy-driver "$MBOX_RELEASE_CLIPPY_DRIVER_PATH" \
    "$MBOX_RELEASE_CLIPPY_DRIVER_SHA256" || return
  "$MBOX_RELEASE_CLIPPY_DRIVER_PATH" "$@"
}
