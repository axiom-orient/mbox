#!/usr/bin/env -S -i PATH=/usr/bin:/bin HOME=/Users/ax LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 /bin/bash
set -euo pipefail

[[ ${MBOX_RELEASE_STARTUP_BOUNDARY-} == mbox-macos-sanitized-v1 ]] || {
  printf 'macos release-check: direct bash invocation is unsupported; use the executable path\n' >&2
  exit 69
}
TMPDIR=$(/usr/bin/getconf DARWIN_USER_TEMP_DIR) || exit 69
export TMPDIR
[[ -d "$TMPDIR" && ! -L "$TMPDIR" ]] || exit 69

SCRIPT_DIR=$(/usr/bin/dirname "${BASH_SOURCE[0]}")
# shellcheck source=scripts/macos/release-tools.sh
source "$SCRIPT_DIR/release-tools.sh"

# Release provenance always runs with an explicit trusted tool contract.  The
# caller's PATH is data only; it is replaced before any command lookup can
# occur.  Same-account mutation of the fixed host/toolchain remains
# NOT_PROVEN, so each security-critical use also rechecks its digest.
export MBOX_RELEASE_PROVENANCE=0
export PATH="$MBOX_RELEASE_SYSTEM_PATH"
export LC_ALL=C

# This is deliberately a host-specific release protocol.  The Darwin linker
# may put path-derived values (for example LC_UUID or code-signature data) in a
# Mach-O image, so this script never claims that a fresh arbitrary checkout
# path is byte-reproducible.  AXD pins the exact binary installed at the fixed
# path below after this protocol has completed.
ROOT=$(cd "$SCRIPT_DIR/../.." && "$MBOX_RELEASE_PWD_PATH" -P)
CANONICAL_REPO="/Users/ax/repoGithub/mbox"
CANONICAL_TARGET="$CANONICAL_REPO/target"
RESERVED_BUILD_NAME=".mbox-release-v2"
RESERVED_BUILD_DIR="$CANONICAL_TARGET/$RESERVED_BUILD_NAME"
RESERVED_MARKER="$RESERVED_BUILD_DIR/$RESERVED_BUILD_NAME.marker"
BUILD_BIN="$RESERVED_BUILD_DIR/release/mbox"
CANONICAL_RELEASE_DIR="$CANONICAL_TARGET/release"
CANONICAL_BIN="$CANONICAL_RELEASE_DIR/mbox"
RECORD_FILE="$CANONICAL_REPO/docs/macos/RELEASE-v0.2.0.sha256"
SCRIPT_PATH="$CANONICAL_REPO/scripts/macos/release-check.sh"
ATOMIC_INSTALL_SOURCE="$CANONICAL_REPO/scripts/macos/atomic_install.rs"
ATOMIC_INSTALL_BIN=
PROTOCOL="mbox-macos-fixed-release-v2"
REPEATABILITY="two-sequential-clean-builds-at-canonical-root"
VERIFICATION="./scripts/verify-macos.sh --release-provenance"
MAX_RECORD_LINES=64
MAX_RECORD_LINE_BYTES=1024
MAX_RECORD_BYTES=32768

# The release protocol is intentionally limited to the fixed operator-owned
# checkout.  These values are captured once from the checked-in path and are
# never obtained from a provenance record.
RUN_UID=$($MBOX_RELEASE_ID_PATH -u)
RUN_GID=$($MBOX_RELEASE_ID_PATH -g)
REPO_DEVICE=
ATOMIC_INSTALL_BIN="$CANONICAL_TARGET/.mbox-atomic-install-v2"

fail() {
  printf 'macos release-check: FAIL: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s [--self-test|--check-record RECORD]\n' "$0" >&2
  exit 2
}

[[ "$ROOT" == "$CANONICAL_REPO" ]] || {
  echo "macos release-check: must run from $CANONICAL_REPO" >&2
  exit 69
}
cd "$ROOT"

[[ $($MBOX_RELEASE_UNAME_PATH -s) == Darwin ]] || {
  echo "macos release-check: must run on Darwin" >&2
  exit 69
}
[[ -x /usr/bin/sandbox-exec ]] || {
  echo "macos release-check: /usr/bin/sandbox-exec is unavailable" >&2
  exit 69
}
mbox_release_root_tool /usr/bin/sandbox-exec || exit 69
for system_tool in \
  "$MBOX_RELEASE_BASH_PATH" "$MBOX_RELEASE_AWK_PATH" "$MBOX_RELEASE_CMP_PATH" \
  "$MBOX_RELEASE_CHMOD_PATH" "$MBOX_RELEASE_CP_PATH" "$MBOX_RELEASE_DIRNAME_PATH" "$MBOX_RELEASE_ENV_PATH" \
  "$MBOX_RELEASE_FIND_PATH" "$MBOX_RELEASE_GREP_PATH" "$MBOX_RELEASE_HEAD_PATH" \
  "$MBOX_RELEASE_ID_PATH" "$MBOX_RELEASE_LN_PATH" "$MBOX_RELEASE_MKDIR_PATH" \
  "$MBOX_RELEASE_MKTEMP_PATH" "$MBOX_RELEASE_MV_PATH" "$MBOX_RELEASE_PWD_PATH" \
  "$MBOX_RELEASE_REALPATH_PATH" "$MBOX_RELEASE_RM_PATH" "$MBOX_RELEASE_SED_PATH" \
  "$MBOX_RELEASE_SHA256SUM_PATH" "$MBOX_RELEASE_SHASUM_PATH" "$MBOX_RELEASE_SORT_PATH" \
  "$MBOX_RELEASE_STAT_PATH" "$MBOX_RELEASE_UNAME_PATH" "$MBOX_RELEASE_XCRUN_PATH" \
  "$MBOX_RELEASE_CLANG_PATH" "$MBOX_RELEASE_GETCONF_PATH"; do
  mbox_release_root_tool "$system_tool" || exit 69
done

reject_external_build_overrides() {
  local name
  # These variables can change code generation, linker selection, SDK input,
  # Cargo's target/profile, or rustup's toolchain selection.  The protocol
  # clears them first and owns their values explicitly below.  PATH is handled
  # separately at process entry and is never consulted from the ambient value.
  for name in \
    CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN RUSTUP_DIST_SERVER RUSTUP_UPDATE_ROOT \
    RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS \
    RUSTC RUSTC_LINKER CARGO RUSTDOCFLAGS \
    RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC \
    CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_JOBS \
    CARGO_BUILD_TARGET CARGO_TARGET_DIR CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
    CARGO_PROFILE_RELEASE_DEBUG CARGO_PROFILE_RELEASE_LTO \
    CARGO_PROFILE_RELEASE_PANIC CARGO_PROFILE_RELEASE_STRIP \
    CARGO_PROFILE_RELEASE_OPT_LEVEL CARGO_PROFILE_RELEASE_RPATH \
    CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS \
    CARGO_PROFILE_RELEASE_INCREMENTAL CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_DEBUG \
    CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_CODEGEN_UNITS \
    CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_LTO CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_PANIC \
    CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_RPATH CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_STRIP \
    CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL \
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS \
    CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS \
    RUSTC_BOOTSTRAP SDKROOT DEVELOPER_DIR MACOSX_DEPLOYMENT_TARGET CC CXX AR \
    CFLAGS CXXFLAGS LDFLAGS SOURCE_DATE_EPOCH ZERO_AR_DATE; do
    unset "$name"
  done
}

reject_external_build_overrides
export HOME=/Users/ax
export RUSTUP_HOME=/Users/ax/.rustup
mbox_release_discover_toolchain || exit 69
export MBOX_RELEASE_PROVENANCE=1
MBOX_RELEASE_LINKER_PATH="$MBOX_RELEASE_CLANG_PATH"
MBOX_RELEASE_LINKER_SHA256=$(mbox_release_hash_file "$MBOX_RELEASE_LINKER_PATH") || exit 69
MBOX_RELEASE_XCRUN_SHA256=$(mbox_release_hash_file "$MBOX_RELEASE_XCRUN_PATH") || exit 69
MBOX_RELEASE_SDK_PATH=$($MBOX_RELEASE_XCRUN_PATH --sdk macosx --show-sdk-path) ||
  fail "xcrun could not resolve the macOS SDK"
MBOX_RELEASE_SDK_PATH=$($MBOX_RELEASE_REALPATH_PATH "$MBOX_RELEASE_SDK_PATH") ||
  fail "could not canonicalize the macOS SDK path"
[[ -d "$MBOX_RELEASE_SDK_PATH" && ! -L "$MBOX_RELEASE_SDK_PATH" ]] ||
  fail "macOS SDK path is not a canonical directory"
export MBOX_RELEASE_LINKER_PATH MBOX_RELEASE_LINKER_SHA256
export MBOX_RELEASE_XCRUN_SHA256 MBOX_RELEASE_SDK_PATH

PACKAGE_VERSION=$($MBOX_RELEASE_SED_PATH -nE 's/^version = "([^\"]+)"$/\1/p' Cargo.toml | $MBOX_RELEASE_HEAD_PATH -n 1)
[[ -n "$PACKAGE_VERSION" ]] || fail "could not derive package version from Cargo.toml"

HOST_OS=$($MBOX_RELEASE_UNAME_PATH -s)
HOST_ARCH=$($MBOX_RELEASE_UNAME_PATH -m)
HOST="$HOST_OS $HOST_ARCH"
RUSTC_VERSION="$MBOX_RELEASE_RUSTC_VERSION"
CARGO_VERSION="$MBOX_RELEASE_CARGO_VERSION"
EXPECTED_VERSION="mbox $PACKAGE_VERSION"
EXPECTED_BUILD_ROOT="$RESERVED_BUILD_DIR"
EXPECTED_BUILD_PATH="$BUILD_BIN"
EXPECTED_INSTALL_PATH="$CANONICAL_BIN"
EXPECTED_BUILD_COMMAND="CARGO_TARGET_DIR=$RESERVED_BUILD_DIR CARGO_INCREMENTAL=0 RUSTFLAGS= CARGO_ENCODED_RUSTFLAGS= CARGO_BUILD_RUSTFLAGS= RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER= CARGO_BUILD_RUSTC_WRAPPER= RUSTC=$MBOX_RELEASE_RUSTC_PATH RUSTC_LINKER=$MBOX_RELEASE_LINKER_PATH SDKROOT=$MBOX_RELEASE_SDK_PATH LC_ALL=C $MBOX_RELEASE_CARGO_PATH build --release --locked --manifest-path $CANONICAL_REPO/Cargo.toml"

digest_for() {
  mbox_release_hash_file "$1"
}

require_regular() {
  local path=$1
  [[ -f "$path" && ! -L "$path" ]] || fail "required regular provenance file is missing or is a symlink"
}

package_build_value() {
  "$MBOX_RELEASE_AWK_PATH" '
    /^\[package\]$/ { in_package = 1; next }
    in_package && /^\[/ { exit }
    in_package && /^[[:space:]]*build[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "", $0)
      sub(/[[:space:]]+#.*$/, "", $0)
      gsub(/^"|"$/, "", $0)
      print $0
      exit
    }
  ' Cargo.toml
}

source_input_list() {
  require_regular Cargo.toml
  require_regular Cargo.lock

  # A second Cargo manifest would change the package graph or workspace
  # interpretation.  It is outside this one-package protocol and fails
  # closed rather than silently escaping the fingerprint.
  local manifest
  while IFS= read -r manifest; do
    [[ "$manifest" == "./Cargo.toml" ]] || \
      fail "unexpected Cargo manifest is outside the fixed input set: $manifest"
  done < <("$MBOX_RELEASE_FIND_PATH" . \( -path ./target -o -path ./.git \) -prune -o -type f -name Cargo.toml -print)

  # Cargo auto-detects build.rs.  An explicitly named, non-root build script
  # is not admitted because its input graph cannot be bounded by this record.
  local declared_build
  declared_build=$(package_build_value)
  case "$declared_build" in
    ""|false|build.rs) ;;
    *) fail "unexpected Cargo build script path: $declared_build" ;;
  esac

  local path relative special
  for path in Cargo.toml Cargo.lock; do
    printf '%s\n' "$path"
  done
  # A repository toolchain file changes which compiler Cargo selects.  Admit
  # only Cargo's two canonical names and fingerprint their complete content;
  # an unrecognised rust-toolchain* file fails closed as an unexpected input.
  for path in rust-toolchain*; do
    [[ -e "$path" || -L "$path" ]] || continue
    case "$path" in
      rust-toolchain|rust-toolchain.toml)
        require_regular "$path"
        printf '%s\n' "$path"
        ;;
      *)
        fail "unexpected toolchain input: $path"
        ;;
    esac
  done
  if [[ -e build.rs || -L build.rs ]]; then
    require_regular build.rs
    printf '%s\n' build.rs
  fi

  [[ -d src && ! -L src ]] || fail "src must be a real directory"
  special=$("$MBOX_RELEASE_FIND_PATH" src ! -type f ! -type d ! -type l -print -quit)
  [[ -z "$special" ]] || fail "unexpected non-regular source input: $special"
  if [[ -n "$("$MBOX_RELEASE_FIND_PATH" src -type l -print -quit)" ]]; then
    fail "symlinked source input is not admitted"
  fi
  while IFS= read -r path; do
    relative=${path#./}
    [[ "$relative" != *$'\n'* && "$relative" != *$'\t'* ]] || \
      fail "source path contains an unsupported control character: $relative"
    printf '%s\n' "$relative"
  done < <("$MBOX_RELEASE_FIND_PATH" src -type f -print)

  if [[ -e .cargo || -L .cargo ]]; then
    [[ -d .cargo && ! -L .cargo ]] || fail ".cargo must be a real directory"
    special=$("$MBOX_RELEASE_FIND_PATH" .cargo ! -type f ! -type d ! -type l -print -quit)
    [[ -z "$special" ]] || fail "unexpected non-regular Cargo config input: $special"
    if [[ -n "$("$MBOX_RELEASE_FIND_PATH" .cargo -type l -print -quit)" ]]; then
      fail "symlinked Cargo config input is not admitted"
    fi
    while IFS= read -r path; do
      relative=${path#./}
      case "$relative" in
        .cargo/config|.cargo/config.toml|.cargo/config.d/*.toml)
          printf '%s\n' "$relative"
          ;;
        *)
          fail "unexpected Cargo config input: $relative"
          ;;
      esac
    done < <("$MBOX_RELEASE_FIND_PATH" .cargo -type f -print)
  fi
}

source_fingerprint() {
  local list_file=$1
  local aggregate_file=$2
  local path file_digest
  source_input_list | LC_ALL=C "$MBOX_RELEASE_SORT_PATH" -u > "$list_file"
  [[ -s "$list_file" ]] || fail "source input list is empty"
  : > "$aggregate_file"
  while IFS= read -r path; do
    require_regular "$path"
    file_digest=$(digest_for "$path")
    # The path and its content digest are both part of the deterministic
    # aggregate.  Sorting is repeated here so callers cannot influence order.
    printf '%s\t%s\n' "$path" "$file_digest" >> "$aggregate_file"
  done < "$list_file"
  LC_ALL=C "$MBOX_RELEASE_SORT_PATH" "$aggregate_file" |
    "$MBOX_RELEASE_SHASUM_PATH" -a 256 | "$MBOX_RELEASE_AWK_PATH" '{print $1}'
}

reset_record_fields() {
  record_protocol=
  record_version=
  record_host=
  record_arch=
  record_rustc=
  record_cargo=
  record_rustc_path=
  record_rustc_sha256=
  record_cargo_path=
  record_cargo_sha256=
  record_rustfmt_path=
  record_rustfmt_sha256=
  record_clippy_driver_path=
  record_clippy_driver_sha256=
  record_linker_path=
  record_linker_sha256=
  record_sdk_path=
  record_xcrun_path=
  record_xcrun_sha256=
  record_hash_path=
  record_hash_sha256=
  record_hash_verify_path=
  record_hash_verify_sha256=
  record_source_fingerprint=
  record_release_helper_sha256=
  record_release_helper_binary_sha256=
  record_build_root=
  record_build_path=
  record_install_path=
  record_build_command=
  record_repeatability=
  record_verification=
  record_sha256=
  seen_protocol=0
  seen_version=0
  seen_host=0
  seen_arch=0
  seen_rustc=0
  seen_cargo=0
  seen_rustc_path=0
  seen_rustc_sha256=0
  seen_cargo_path=0
  seen_cargo_sha256=0
  seen_rustfmt_path=0
  seen_rustfmt_sha256=0
  seen_clippy_driver_path=0
  seen_clippy_driver_sha256=0
  seen_linker_path=0
  seen_linker_sha256=0
  seen_sdk_path=0
  seen_xcrun_path=0
  seen_xcrun_sha256=0
  seen_hash_path=0
  seen_hash_sha256=0
  seen_hash_verify_path=0
  seen_hash_verify_sha256=0
  seen_source_fingerprint=0
  seen_release_helper_sha256=0
  seen_release_helper_binary_sha256=0
  seen_build_root=0
  seen_build_path=0
  seen_install_path=0
  seen_build_command=0
  seen_repeatability=0
  seen_verification=0
  seen_sha256=0
}

reject_unsafe_record_value() {
  local field=$1
  local value=$2
  # Values are data only.  Reject shell metacharacters before they can reach
  # diagnostics or any future protocol extension.  No record value is ever
  # used as shell source, an identifier, or a command argument.
  if [[ "$value" == *'$'* || "$value" == *'`'* || "$value" == *'\\'* ||
    "$value" == *';'* || "$value" == *'|'* || "$value" == *'&'* ||
    "$value" == *'<'* || "$value" == *'>'* || "$value" == *$'\r'* ||
    "$value" == *$'\t'* ]]; then
    fail "unsafe provenance field: $field"
  fi
}

assign_record_field() {
  local field=$1
  local value=$2
  [[ ${#value} -le "$MAX_RECORD_LINE_BYTES" ]] || \
    fail "provenance field is too long: $field"
  reject_unsafe_record_value "$field" "$value"
  case "$field" in
    protocol)
      [[ $seen_protocol -eq 0 ]] || fail "duplicate provenance field: protocol"
      record_protocol=$value; seen_protocol=1 ;;
    version)
      [[ $seen_version -eq 0 ]] || fail "duplicate provenance field: version"
      record_version=$value; seen_version=1 ;;
    host)
      [[ $seen_host -eq 0 ]] || fail "duplicate provenance field: host"
      record_host=$value; seen_host=1 ;;
    arch)
      [[ $seen_arch -eq 0 ]] || fail "duplicate provenance field: arch"
      record_arch=$value; seen_arch=1 ;;
    rustc)
      [[ $seen_rustc -eq 0 ]] || fail "duplicate provenance field: rustc"
      record_rustc=$value; seen_rustc=1 ;;
    cargo)
      [[ $seen_cargo -eq 0 ]] || fail "duplicate provenance field: cargo"
      record_cargo=$value; seen_cargo=1 ;;
    rustc-path)
      [[ $seen_rustc_path -eq 0 ]] || fail "duplicate provenance field: rustc-path"
      record_rustc_path=$value; seen_rustc_path=1 ;;
    rustc-sha256)
      [[ $seen_rustc_sha256 -eq 0 ]] || fail "duplicate provenance field: rustc-sha256"
      record_rustc_sha256=$value; seen_rustc_sha256=1 ;;
    cargo-path)
      [[ $seen_cargo_path -eq 0 ]] || fail "duplicate provenance field: cargo-path"
      record_cargo_path=$value; seen_cargo_path=1 ;;
    cargo-sha256)
      [[ $seen_cargo_sha256 -eq 0 ]] || fail "duplicate provenance field: cargo-sha256"
      record_cargo_sha256=$value; seen_cargo_sha256=1 ;;
    rustfmt-path)
      [[ $seen_rustfmt_path -eq 0 ]] || fail "duplicate provenance field: rustfmt-path"
      record_rustfmt_path=$value; seen_rustfmt_path=1 ;;
    rustfmt-sha256)
      [[ $seen_rustfmt_sha256 -eq 0 ]] || fail "duplicate provenance field: rustfmt-sha256"
      record_rustfmt_sha256=$value; seen_rustfmt_sha256=1 ;;
    clippy-driver-path)
      [[ $seen_clippy_driver_path -eq 0 ]] || fail "duplicate provenance field: clippy-driver-path"
      record_clippy_driver_path=$value; seen_clippy_driver_path=1 ;;
    clippy-driver-sha256)
      [[ $seen_clippy_driver_sha256 -eq 0 ]] || fail "duplicate provenance field: clippy-driver-sha256"
      record_clippy_driver_sha256=$value; seen_clippy_driver_sha256=1 ;;
    linker-path)
      [[ $seen_linker_path -eq 0 ]] || fail "duplicate provenance field: linker-path"
      record_linker_path=$value; seen_linker_path=1 ;;
    linker-sha256)
      [[ $seen_linker_sha256 -eq 0 ]] || fail "duplicate provenance field: linker-sha256"
      record_linker_sha256=$value; seen_linker_sha256=1 ;;
    sdk-path)
      [[ $seen_sdk_path -eq 0 ]] || fail "duplicate provenance field: sdk-path"
      record_sdk_path=$value; seen_sdk_path=1 ;;
    xcrun-path)
      [[ $seen_xcrun_path -eq 0 ]] || fail "duplicate provenance field: xcrun-path"
      record_xcrun_path=$value; seen_xcrun_path=1 ;;
    xcrun-sha256)
      [[ $seen_xcrun_sha256 -eq 0 ]] || fail "duplicate provenance field: xcrun-sha256"
      record_xcrun_sha256=$value; seen_xcrun_sha256=1 ;;
    hash-path)
      [[ $seen_hash_path -eq 0 ]] || fail "duplicate provenance field: hash-path"
      record_hash_path=$value; seen_hash_path=1 ;;
    hash-sha256)
      [[ $seen_hash_sha256 -eq 0 ]] || fail "duplicate provenance field: hash-sha256"
      record_hash_sha256=$value; seen_hash_sha256=1 ;;
    hash-verify-path)
      [[ $seen_hash_verify_path -eq 0 ]] || fail "duplicate provenance field: hash-verify-path"
      record_hash_verify_path=$value; seen_hash_verify_path=1 ;;
    hash-verify-sha256)
      [[ $seen_hash_verify_sha256 -eq 0 ]] || fail "duplicate provenance field: hash-verify-sha256"
      record_hash_verify_sha256=$value; seen_hash_verify_sha256=1 ;;
    source-fingerprint)
      [[ $seen_source_fingerprint -eq 0 ]] || fail "duplicate provenance field: source-fingerprint"
      record_source_fingerprint=$value; seen_source_fingerprint=1 ;;
    release-helper-sha256)
      [[ $seen_release_helper_sha256 -eq 0 ]] || fail "duplicate provenance field: release-helper-sha256"
      record_release_helper_sha256=$value; seen_release_helper_sha256=1 ;;
    release-helper-binary-sha256)
      [[ $seen_release_helper_binary_sha256 -eq 0 ]] || fail "duplicate provenance field: release-helper-binary-sha256"
      record_release_helper_binary_sha256=$value; seen_release_helper_binary_sha256=1 ;;
    build-root)
      [[ $seen_build_root -eq 0 ]] || fail "duplicate provenance field: build-root"
      record_build_root=$value; seen_build_root=1 ;;
    build-path)
      [[ $seen_build_path -eq 0 ]] || fail "duplicate provenance field: build-path"
      record_build_path=$value; seen_build_path=1 ;;
    install-path)
      [[ $seen_install_path -eq 0 ]] || fail "duplicate provenance field: install-path"
      record_install_path=$value; seen_install_path=1 ;;
    build-command)
      [[ $seen_build_command -eq 0 ]] || fail "duplicate provenance field: build-command"
      record_build_command=$value; seen_build_command=1 ;;
    repeatability)
      [[ $seen_repeatability -eq 0 ]] || fail "duplicate provenance field: repeatability"
      record_repeatability=$value; seen_repeatability=1 ;;
    verification)
      [[ $seen_verification -eq 0 ]] || fail "duplicate provenance field: verification"
      record_verification=$value; seen_verification=1 ;;
    sha256)
      [[ $seen_sha256 -eq 0 ]] || fail "duplicate provenance field: sha256"
      record_sha256=$value; seen_sha256=1 ;;
    *) fail "unexpected provenance field: $field" ;;
  esac
}

parse_record() {
  local record_path=$1
  local line key value line_number record_bytes
  require_regular "$record_path"
  reset_record_fields
  line_number=0
  record_bytes=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    [[ $line_number -le "$MAX_RECORD_LINES" ]] || \
      fail "provenance record has too many lines"
    record_bytes=$((record_bytes + ${#line} + 1))
    [[ $record_bytes -le "$MAX_RECORD_BYTES" ]] || \
      fail "provenance record is too large"
    [[ ${#line} -le "$MAX_RECORD_LINE_BYTES" ]] || \
      fail "provenance record line is too long"
    case "$line" in
      ""|\#*) continue ;;
      *=*)
        key=${line%%=*}
        value=${line#*=}
        ;;
      *) fail "malformed provenance record line $line_number" ;;
    esac
    [[ "$key" =~ ^[a-z][a-z0-9-]{0,31}$ ]] || fail "invalid provenance field name"
    assign_record_field "$key" "$value"
  done < "$record_path"

  local required
  for required in \
    protocol version host arch rustc cargo rustc-path rustc-sha256 cargo-path cargo-sha256 \
    rustfmt-path rustfmt-sha256 clippy-driver-path clippy-driver-sha256 linker-path linker-sha256 \
    sdk-path xcrun-path xcrun-sha256 hash-path hash-sha256 hash-verify-path hash-verify-sha256 \
    source-fingerprint release-helper-sha256 release-helper-binary-sha256 build-root \
    build-path install-path build-command repeatability verification sha256; do
    case "$required" in
      protocol) [[ $seen_protocol -eq 1 && -n "$record_protocol" ]] || fail "missing or empty provenance field: $required" ;;
      version) [[ $seen_version -eq 1 && -n "$record_version" ]] || fail "missing or empty provenance field: $required" ;;
      host) [[ $seen_host -eq 1 && -n "$record_host" ]] || fail "missing or empty provenance field: $required" ;;
      arch) [[ $seen_arch -eq 1 && -n "$record_arch" ]] || fail "missing or empty provenance field: $required" ;;
      rustc) [[ $seen_rustc -eq 1 && -n "$record_rustc" ]] || fail "missing or empty provenance field: $required" ;;
      cargo) [[ $seen_cargo -eq 1 && -n "$record_cargo" ]] || fail "missing or empty provenance field: $required" ;;
      rustc-path) [[ $seen_rustc_path -eq 1 && -n "$record_rustc_path" ]] || fail "missing or empty provenance field: $required" ;;
      rustc-sha256) [[ $seen_rustc_sha256 -eq 1 && -n "$record_rustc_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      cargo-path) [[ $seen_cargo_path -eq 1 && -n "$record_cargo_path" ]] || fail "missing or empty provenance field: $required" ;;
      cargo-sha256) [[ $seen_cargo_sha256 -eq 1 && -n "$record_cargo_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      rustfmt-path) [[ $seen_rustfmt_path -eq 1 && -n "$record_rustfmt_path" ]] || fail "missing or empty provenance field: $required" ;;
      rustfmt-sha256) [[ $seen_rustfmt_sha256 -eq 1 && -n "$record_rustfmt_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      clippy-driver-path) [[ $seen_clippy_driver_path -eq 1 && -n "$record_clippy_driver_path" ]] || fail "missing or empty provenance field: $required" ;;
      clippy-driver-sha256) [[ $seen_clippy_driver_sha256 -eq 1 && -n "$record_clippy_driver_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      linker-path) [[ $seen_linker_path -eq 1 && -n "$record_linker_path" ]] || fail "missing or empty provenance field: $required" ;;
      linker-sha256) [[ $seen_linker_sha256 -eq 1 && -n "$record_linker_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      sdk-path) [[ $seen_sdk_path -eq 1 && -n "$record_sdk_path" ]] || fail "missing or empty provenance field: $required" ;;
      xcrun-path) [[ $seen_xcrun_path -eq 1 && -n "$record_xcrun_path" ]] || fail "missing or empty provenance field: $required" ;;
      xcrun-sha256) [[ $seen_xcrun_sha256 -eq 1 && -n "$record_xcrun_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      hash-path) [[ $seen_hash_path -eq 1 && -n "$record_hash_path" ]] || fail "missing or empty provenance field: $required" ;;
      hash-sha256) [[ $seen_hash_sha256 -eq 1 && -n "$record_hash_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      hash-verify-path) [[ $seen_hash_verify_path -eq 1 && -n "$record_hash_verify_path" ]] || fail "missing or empty provenance field: $required" ;;
      hash-verify-sha256) [[ $seen_hash_verify_sha256 -eq 1 && -n "$record_hash_verify_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      source-fingerprint) [[ $seen_source_fingerprint -eq 1 && -n "$record_source_fingerprint" ]] || fail "missing or empty provenance field: $required" ;;
      release-helper-sha256) [[ $seen_release_helper_sha256 -eq 1 && -n "$record_release_helper_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      release-helper-binary-sha256) [[ $seen_release_helper_binary_sha256 -eq 1 && -n "$record_release_helper_binary_sha256" ]] || fail "missing or empty provenance field: $required" ;;
      build-root) [[ $seen_build_root -eq 1 && -n "$record_build_root" ]] || fail "missing or empty provenance field: $required" ;;
      build-path) [[ $seen_build_path -eq 1 && -n "$record_build_path" ]] || fail "missing or empty provenance field: $required" ;;
      install-path) [[ $seen_install_path -eq 1 && -n "$record_install_path" ]] || fail "missing or empty provenance field: $required" ;;
      build-command) [[ $seen_build_command -eq 1 && -n "$record_build_command" ]] || fail "missing or empty provenance field: $required" ;;
      repeatability) [[ $seen_repeatability -eq 1 && -n "$record_repeatability" ]] || fail "missing or empty provenance field: $required" ;;
      verification) [[ $seen_verification -eq 1 && -n "$record_verification" ]] || fail "missing or empty provenance field: $required" ;;
      sha256) [[ $seen_sha256 -eq 1 && -n "$record_sha256" ]] || fail "missing or empty provenance field: $required" ;;
    esac
  done
  [[ "$record_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "provenance sha256 is not lowercase hexadecimal"
  [[ "$record_source_fingerprint" =~ ^[0-9a-f]{64}$ ]] || fail "source fingerprint is not lowercase hexadecimal"
  [[ "$record_release_helper_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "release helper sha256 is not lowercase hexadecimal"
  for digest in "$record_rustc_sha256" "$record_cargo_sha256" "$record_rustfmt_sha256" \
    "$record_clippy_driver_sha256" "$record_linker_sha256" "$record_xcrun_sha256" \
    "$record_hash_sha256" "$record_hash_verify_sha256" "$record_release_helper_binary_sha256"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "provenance tool digest is not lowercase hexadecimal"
  done
}

validate_record_identity() {
  local current_source=$1
  local current_helper
  require_regular "$ATOMIC_INSTALL_SOURCE"
  current_helper=$(digest_for "$ATOMIC_INSTALL_SOURCE")
  [[ "$record_protocol" == "$PROTOCOL" ]] || fail "provenance protocol mismatch"
  [[ "$record_version" == "$EXPECTED_VERSION" ]] || fail "provenance mbox version mismatch"
  [[ "$record_host" == "$HOST" ]] || fail "provenance host mismatch"
  [[ "$record_arch" == "$HOST_ARCH" ]] || fail "provenance architecture mismatch"
  [[ "$record_rustc" == "$RUSTC_VERSION" ]] || fail "provenance rustc version mismatch"
  [[ "$record_cargo" == "$CARGO_VERSION" ]] || fail "provenance cargo version mismatch"
  [[ "$record_rustc_path" == "$MBOX_RELEASE_RUSTC_PATH" ]] || fail "provenance rustc path mismatch"
  [[ "$record_cargo_path" == "$MBOX_RELEASE_CARGO_PATH" ]] || fail "provenance cargo path mismatch"
  [[ "$record_rustfmt_path" == "$MBOX_RELEASE_RUSTFMT_PATH" ]] || fail "provenance rustfmt path mismatch"
  [[ "$record_clippy_driver_path" == "$MBOX_RELEASE_CLIPPY_DRIVER_PATH" ]] || fail "provenance clippy-driver path mismatch"
  [[ "$record_linker_path" == "$MBOX_RELEASE_LINKER_PATH" ]] || fail "provenance linker path mismatch"
  [[ "$record_sdk_path" == "$MBOX_RELEASE_SDK_PATH" ]] || fail "provenance SDK path mismatch"
  [[ "$record_xcrun_path" == "$MBOX_RELEASE_XCRUN_PATH" ]] || fail "provenance xcrun path mismatch"
  [[ "$record_hash_path" == "$MBOX_RELEASE_SHASUM_PATH" ]] || fail "provenance hash path mismatch"
  [[ "$record_hash_verify_path" == "$MBOX_RELEASE_SHA256SUM_PATH" ]] || fail "provenance hash verifier path mismatch"
  [[ "$record_rustc_sha256" == "$MBOX_RELEASE_RUSTC_SHA256" ]] || fail "provenance rustc digest mismatch"
  [[ "$record_cargo_sha256" == "$MBOX_RELEASE_CARGO_SHA256" ]] || fail "provenance cargo digest mismatch"
  [[ "$record_rustfmt_sha256" == "$MBOX_RELEASE_RUSTFMT_SHA256" ]] || fail "provenance rustfmt digest mismatch"
  [[ "$record_clippy_driver_sha256" == "$MBOX_RELEASE_CLIPPY_DRIVER_SHA256" ]] || fail "provenance clippy-driver digest mismatch"
  [[ "$record_linker_sha256" == "$MBOX_RELEASE_LINKER_SHA256" ]] || fail "provenance linker digest mismatch"
  [[ "$record_xcrun_sha256" == "$MBOX_RELEASE_XCRUN_SHA256" ]] || fail "provenance xcrun digest mismatch"
  [[ "$record_hash_sha256" == "$MBOX_RELEASE_SHASUM_SHA256" ]] || fail "provenance hash digest mismatch"
  [[ "$record_hash_verify_sha256" == "$MBOX_RELEASE_SHA256SUM_SHA256" ]] || fail "provenance hash verifier digest mismatch"
  mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$record_rustc_sha256" || return
  mbox_release_recheck_tool cargo "$MBOX_RELEASE_CARGO_PATH" "$record_cargo_sha256" || return
  mbox_release_recheck_tool rustfmt "$MBOX_RELEASE_RUSTFMT_PATH" "$record_rustfmt_sha256" || return
  mbox_release_recheck_tool clippy-driver "$MBOX_RELEASE_CLIPPY_DRIVER_PATH" "$record_clippy_driver_sha256" || return
  mbox_release_recheck_tool linker "$MBOX_RELEASE_LINKER_PATH" "$record_linker_sha256" || return
  mbox_release_recheck_tool xcrun "$MBOX_RELEASE_XCRUN_PATH" "$record_xcrun_sha256" || return
  [[ "$($MBOX_RELEASE_SHA256SUM_PATH "$MBOX_RELEASE_SHA256SUM_PATH" | $MBOX_RELEASE_AWK_PATH '{print $1}')" == "$record_hash_verify_sha256" ]] ||
    fail "provenance hash verifier changed before use"
  [[ "$($MBOX_RELEASE_SHA256SUM_PATH "$MBOX_RELEASE_SHASUM_PATH" | $MBOX_RELEASE_AWK_PATH '{print $1}')" == "$record_hash_sha256" ]] ||
    fail "provenance hash utility changed before use"
  [[ "$record_source_fingerprint" == "$current_source" ]] || fail "provenance source fingerprint mismatch"
  [[ "$record_release_helper_sha256" == "$current_helper" ]] || fail "release helper source digest mismatch"
  [[ "$record_build_root" == "$EXPECTED_BUILD_ROOT" ]] || fail "provenance canonical build root mismatch"
  [[ "$record_build_path" == "$EXPECTED_BUILD_PATH" ]] || fail "provenance canonical binary path mismatch"
  [[ "$record_install_path" == "$EXPECTED_INSTALL_PATH" ]] || fail "provenance canonical install path mismatch"
  [[ "$record_build_command" == "$EXPECTED_BUILD_COMMAND" ]] || fail "provenance build protocol command mismatch"
  [[ "$record_repeatability" == "$REPEATABILITY" ]] || fail "provenance repeatability protocol mismatch"
  [[ "$record_verification" == "$VERIFICATION" ]] || fail "provenance verification command mismatch"
}

validate_compiled_helper() {
  require_regular "$ATOMIC_INSTALL_BIN"
  [[ -x "$ATOMIC_INSTALL_BIN" ]] || fail "compiled release helper is not executable"
  local helper_digest
  helper_digest=$(digest_for "$ATOMIC_INSTALL_BIN")
  [[ "$helper_digest" == "$record_release_helper_binary_sha256" ]] ||
    fail "compiled release helper digest mismatch"
  # Rehash immediately before the helper is used.  The fixed path and digest
  # are protocol data, never a command selector.
  helper_digest=$(digest_for "$ATOMIC_INSTALL_BIN")
  [[ "$helper_digest" == "$record_release_helper_binary_sha256" ]] ||
    fail "compiled release helper changed before use"
}

validate_current_binary() {
  [[ "$CANONICAL_BIN" == "$CANONICAL_REPO/target/release/mbox" ]] || \
    fail "canonical binary path invariant was changed"
  require_regular "$CANONICAL_BIN"
  [[ -x "$CANONICAL_BIN" ]] || fail "canonical release binary is not executable"
  local actual_digest
  actual_digest=$(digest_for "$CANONICAL_BIN")
  [[ "$actual_digest" == "$record_sha256" ]] || \
    fail "release sha256 mismatch"
  [[ "$($CANONICAL_BIN --version)" == "$EXPECTED_VERSION" ]] || \
    fail "canonical release version mismatch"
  [[ "$($CANONICAL_BIN --help | $MBOX_RELEASE_SED_PATH -n '1p')" == "$EXPECTED_VERSION" ]] || \
    fail "canonical release help version mismatch"
}

make_temp_root() {
  local tmp_base
  tmp_base=${TMPDIR:-/tmp}
  [[ -d "$tmp_base" && ! -L "$tmp_base" ]] || fail "TMPDIR must be a real directory"
  tmp_base=$(cd "$tmp_base" && "$MBOX_RELEASE_PWD_PATH" -P)
  RELEASE_TMP=$($MBOX_RELEASE_MKTEMP_PATH -d "$tmp_base/mbox-fixed-release.XXXXXX")
  RELEASE_TMP=$(cd "$RELEASE_TMP" && "$MBOX_RELEASE_PWD_PATH" -P)
  [[ "$RELEASE_TMP" == "$tmp_base/mbox-fixed-release."* ]] || \
    fail "temporary protocol root escaped its validated prefix"
  TMP_BASE=$tmp_base
  trap cleanup_temp EXIT HUP INT TERM
}

cleanup_temp() {
  if [[ -n "${RELEASE_TMP-}" && "$RELEASE_TMP" == "${TMP_BASE-}/mbox-fixed-release."* && -d "$RELEASE_TMP" && ! -L "$RELEASE_TMP" ]]; then
    $MBOX_RELEASE_RM_PATH -rf -- "$RELEASE_TMP"
  fi
}

assert_no_symlink_components() {
  local path=$1
  local prefix component
  local -a components
  [[ "$path" == /* ]] || fail "fixed path is not absolute"
  prefix=
  IFS=/ read -r -a components <<< "${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || \
      fail "fixed path contains an invalid component"
    prefix="${prefix}/${component}"
    if [[ -e "$prefix" || -L "$prefix" ]]; then
      [[ ! -L "$prefix" ]] || fail "fixed path contains a symlink component"
    fi
  done
}

assert_owned_directory() {
  local path=$1
  local expected_device=$2
  local uid gid mode device
  [[ -d "$path" && ! -L "$path" ]] || fail "required fixed directory is missing or a symlink"
  uid=$($MBOX_RELEASE_STAT_PATH -f '%u' "$path") || fail "could not inspect fixed directory owner"
  gid=$($MBOX_RELEASE_STAT_PATH -f '%g' "$path") || fail "could not inspect fixed directory group"
  [[ "$uid" == "$RUN_UID" && "$gid" == "$RUN_GID" ]] || \
    fail "fixed build directory owner mismatch"
  mode=$($MBOX_RELEASE_STAT_PATH -f '%Lp' "$path") || fail "could not inspect fixed directory mode"
  [[ "$mode" =~ ^[0-7]{3}$ ]] || fail "fixed build directory mode is invalid"
  (( (8#$mode & 022) == 0 )) || fail "fixed build directory is group/other writable"
  device=$($MBOX_RELEASE_STAT_PATH -f '%d' "$path") || fail "could not inspect fixed directory device"
  [[ "$device" == "$expected_device" ]] || fail "fixed build directory crosses a filesystem"
}

assert_owned_regular_file() {
  local path=$1
  local expected_device=$2
  local uid gid mode device
  [[ -f "$path" && ! -L "$path" ]] || fail "required fixed file is missing or a symlink"
  uid=$($MBOX_RELEASE_STAT_PATH -f '%u' "$path") || fail "could not inspect fixed file owner"
  gid=$($MBOX_RELEASE_STAT_PATH -f '%g' "$path") || fail "could not inspect fixed file group"
  [[ "$uid" == "$RUN_UID" && "$gid" == "$RUN_GID" ]] || \
    fail "fixed file owner mismatch"
  mode=$($MBOX_RELEASE_STAT_PATH -f '%Lp' "$path") || fail "could not inspect fixed file mode"
  [[ "$mode" =~ ^[0-7]{3}$ ]] || fail "fixed file mode is invalid"
  (( (8#$mode & 022) == 0 )) || fail "fixed file is group/other writable"
  device=$($MBOX_RELEASE_STAT_PATH -f '%d' "$path") || fail "could not inspect fixed file device"
  [[ "$device" == "$expected_device" ]] || fail "fixed file crosses a filesystem"
}

assert_fixed_layout() {
  [[ "$CANONICAL_REPO" == "/Users/ax/repoGithub/mbox" ]] || \
    fail "canonical repository path invariant was changed"
  [[ "$CANONICAL_TARGET" == "$CANONICAL_REPO/target" ]] || \
    fail "canonical target path invariant was changed"
  [[ "$RESERVED_BUILD_DIR" == "$CANONICAL_TARGET/$RESERVED_BUILD_NAME" ]] || \
    fail "reserved build path invariant was changed"
  [[ "$CANONICAL_RELEASE_DIR" == "$CANONICAL_TARGET/release" ]] || \
    fail "canonical install directory invariant was changed"
  [[ "$CANONICAL_BIN" == "$CANONICAL_RELEASE_DIR/mbox" ]] || \
    fail "canonical install path invariant was changed"
  assert_no_symlink_components "$CANONICAL_REPO"
  assert_no_symlink_components "$CANONICAL_TARGET"
  REPO_DEVICE=$($MBOX_RELEASE_STAT_PATH -f '%d' "$CANONICAL_REPO") || fail "could not inspect repository device"
  assert_owned_directory "$CANONICAL_REPO" "$REPO_DEVICE"
  if [[ -L "$CANONICAL_TARGET" || -e "$CANONICAL_TARGET" && ! -d "$CANONICAL_TARGET" ]]; then
    fail "canonical target is not a real directory"
  fi
  if [[ ! -e "$CANONICAL_TARGET" ]]; then
    (umask 077; $MBOX_RELEASE_MKDIR_PATH -- "$CANONICAL_TARGET") || fail "could not create canonical target"
  fi
  assert_no_symlink_components "$CANONICAL_TARGET"
  assert_owned_directory "$CANONICAL_TARGET" "$REPO_DEVICE"
}

marker_expected_file() {
  local path=$1
  printf 'protocol=%s\nversion=%s\n' "$PROTOCOL" "$EXPECTED_VERSION" > "$path"
}

require_reserved_marker() {
  assert_owned_regular_file "$RESERVED_MARKER" "$REPO_DEVICE"
  marker_expected_file "$RELEASE_TMP/expected-reserved-marker"
  $MBOX_RELEASE_CMP_PATH -s "$RELEASE_TMP/expected-reserved-marker" "$RESERVED_MARKER" || \
    fail "reserved build directory ownership marker mismatch"
}

assert_reserved_tree_safe() {
  local device_file symlink_file entry_device entry_type
  device_file="$RELEASE_TMP/reserved-devices"
  symlink_file="$RELEASE_TMP/reserved-symlinks"
  if ! $MBOX_RELEASE_FIND_PATH -P -x "$RESERVED_BUILD_DIR" -exec $MBOX_RELEASE_STAT_PATH -f '%d %HT' '{}' + >"$device_file"; then
    fail "could not inspect reserved build tree"
  fi
  while IFS=' ' read -r entry_device entry_type; do
    [[ -n "$entry_device" && "$entry_device" == "$REPO_DEVICE" ]] || \
      fail "reserved build tree crosses a filesystem or mount"
  done < "$device_file"
  if ! $MBOX_RELEASE_FIND_PATH -P -x "$RESERVED_BUILD_DIR" -type l -print -quit >"$symlink_file"; then
    fail "could not inspect reserved build symlinks"
  fi
  [[ ! -s "$symlink_file" ]] || fail "reserved build tree contains a symlink"
}

prepare_reserved_build() {
  assert_fixed_layout
  if [[ -e "$RESERVED_BUILD_DIR" || -L "$RESERVED_BUILD_DIR" ]]; then
    assert_no_symlink_components "$RESERVED_BUILD_DIR"
    assert_owned_directory "$RESERVED_BUILD_DIR" "$REPO_DEVICE"
    require_reserved_marker
    assert_reserved_tree_safe
    # `find -x` is intentional: it cannot descend into a mounted filesystem.
    # The preceding device/type audit rejects such a tree before deletion.
    if ! $MBOX_RELEASE_FIND_PATH -P -x "$RESERVED_BUILD_DIR" -depth -mindepth 1 -delete; then
      fail "could not safely clean the reserved build directory"
    fi
  else
    (umask 077; $MBOX_RELEASE_MKDIR_PATH -- "$RESERVED_BUILD_DIR") || \
      fail "could not create reserved build directory"
  fi
  assert_no_symlink_components "$RESERVED_BUILD_DIR"
  assert_owned_directory "$RESERVED_BUILD_DIR" "$REPO_DEVICE"
  marker_expected_file "$RELEASE_TMP/new-reserved-marker"
  if ! $MBOX_RELEASE_MV_PATH -f -- "$RELEASE_TMP/new-reserved-marker" "$RESERVED_MARKER"; then
    fail "could not install reserved build ownership marker"
  fi
  require_reserved_marker
}

prepare_install_directory() {
  assert_fixed_layout
  if [[ -L "$CANONICAL_RELEASE_DIR" || -e "$CANONICAL_RELEASE_DIR" && ! -d "$CANONICAL_RELEASE_DIR" ]]; then
    fail "canonical install directory is not a real directory"
  fi
  if [[ ! -e "$CANONICAL_RELEASE_DIR" ]]; then
    (umask 077; $MBOX_RELEASE_MKDIR_PATH -- "$CANONICAL_RELEASE_DIR") || fail "could not create canonical install directory"
  fi
  assert_no_symlink_components "$CANONICAL_RELEASE_DIR"
  assert_owned_directory "$CANONICAL_RELEASE_DIR" "$REPO_DEVICE"
  if [[ -L "$CANONICAL_BIN" ]]; then
    fail "canonical install binary must not be a symlink"
  fi
  if [[ -e "$CANONICAL_BIN" && ! -f "$CANONICAL_BIN" ]]; then
    fail "canonical install path is not a regular file"
  fi
}

compile_atomic_install_helper() {
  local helper_path="$ATOMIC_INSTALL_BIN"
  require_regular "$ATOMIC_INSTALL_SOURCE"
  [[ "$(digest_for "$ATOMIC_INSTALL_SOURCE")" == "$record_release_helper_sha256" ]] || \
    fail "release helper source changed before compilation"
  assert_fixed_layout
  if [[ -L "$helper_path" || -e "$helper_path" && ! -f "$helper_path" ]]; then
    fail "fixed compiled release helper path is not a regular file"
  fi
  mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$record_rustc_sha256" || return
  "$MBOX_RELEASE_ENV_PATH" -i \
    HOME=/Users/ax RUSTUP_HOME=/Users/ax/.rustup \
    PATH="$MBOX_RELEASE_TOOLCHAIN_BIN:$MBOX_RELEASE_SYSTEM_PATH" \
    TMPDIR=/tmp LC_ALL=C \
    "$MBOX_RELEASE_RUSTC_PATH" --edition=2021 -D warnings -C opt-level=2 -C panic=abort \
    "$ATOMIC_INSTALL_SOURCE" -o "$helper_path"
  require_regular "$helper_path"
  [[ -x "$helper_path" ]] || fail "compiled release helper is not executable"
  ATOMIC_INSTALL_BIN="$helper_path"
}

assert_no_atomic_temps() {
  local directory=$1
  local remnant
  remnant=$($MBOX_RELEASE_FIND_PATH -P "$directory" -maxdepth 1 -name '.mbox.atomic.*' -print -quit)
  [[ -z "$remnant" ]] || fail "atomic installer left a temp remnant: $remnant"
}

atomic_install_self_test() {
  local helper=$1
  local root="$RELEASE_TMP/atomic-install-self-test"
  local fixture release source sentinel before after target target_before target_after
  $MBOX_RELEASE_MKDIR_PATH -- "$root"

  fixture="$root/hardlink"
  release="$fixture/release"
  source="$fixture/source"
  sentinel="$fixture/sentinel"
  $MBOX_RELEASE_MKDIR_PATH -- "$fixture"
  $MBOX_RELEASE_MKDIR_PATH -- "$release"
  printf 'replacement\n' >"$source"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$source"
  printf 'sentinel\n' >"$sentinel"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$sentinel"
  $MBOX_RELEASE_LN_PATH -- "$sentinel" "$release/mbox"
  before=$($MBOX_RELEASE_STAT_PATH -f '%i %l %z' "$sentinel")
  if "$helper" "$source" "$release" >"$fixture/log" 2>&1; then
    fail "atomic installer accepted a hardlinked destination"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'exactly one hard link' "$fixture/log" || \
    fail "hardlinked destination failure did not identify the hard-link gate"
  after=$($MBOX_RELEASE_STAT_PATH -f '%i %l %z' "$sentinel")
  [[ "$before" == "$after" ]] || fail "hardlinked sentinel changed"
  $MBOX_RELEASE_CMP_PATH -s "$sentinel" "$release/mbox" || fail "hardlinked destination bytes changed"
  assert_no_atomic_temps "$release"

  fixture="$root/symlink"
  release="$fixture/release"
  source="$fixture/source"
  target="$fixture/target"
  $MBOX_RELEASE_MKDIR_PATH -- "$fixture"
  $MBOX_RELEASE_MKDIR_PATH -- "$release"
  printf 'replacement\n' >"$source"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$source"
  printf 'symlink-target\n' >"$target"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$target"
  $MBOX_RELEASE_LN_PATH -s -- "$target" "$release/mbox"
  target_before=$($MBOX_RELEASE_STAT_PATH -f '%i %z' "$target")
  if "$helper" "$source" "$release" >"$fixture/log" 2>&1; then
    fail "atomic installer accepted a symlink destination"
  fi
  target_after=$($MBOX_RELEASE_STAT_PATH -f '%i %z' "$target")
  [[ "$target_before" == "$target_after" ]] || fail "symlink target identity changed"
  [[ -L "$release/mbox" ]] || fail "symlink destination was unexpectedly replaced"
  assert_no_atomic_temps "$release"

  fixture="$root/unsafe-directory"
  release="$fixture/release"
  source="$fixture/source"
  $MBOX_RELEASE_MKDIR_PATH -- "$fixture"
  $MBOX_RELEASE_MKDIR_PATH -- "$release"
  "$MBOX_RELEASE_CHMOD_PATH" 777 "$release"
  printf 'replacement\n' >"$source"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$source"
  if "$helper" "$source" "$release" >"$fixture/log" 2>&1; then
    fail "atomic installer accepted an unsafe release directory"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'unsafe permissions' "$fixture/log" || \
    fail "unsafe directory failure did not identify the mode gate"
  assert_no_atomic_temps "$release"

  fixture="$root/wrong-destination-mode"
  release="$fixture/release"
  source="$fixture/source"
  $MBOX_RELEASE_MKDIR_PATH -- "$fixture"
  $MBOX_RELEASE_MKDIR_PATH -- "$release"
  printf 'replacement\n' >"$source"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$source"
  printf 'old\n' >"$release/mbox"
  "$MBOX_RELEASE_CHMOD_PATH" 644 "$release/mbox"
  if "$helper" "$source" "$release" >"$fixture/log" 2>&1; then
    fail "atomic installer accepted a non-executable destination"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'not executable' "$fixture/log" || \
    fail "destination mode failure did not identify the executable gate"
  assert_no_atomic_temps "$release"

  fixture="$root/replacement"
  release="$fixture/release"
  source="$fixture/source"
  $MBOX_RELEASE_MKDIR_PATH -- "$fixture"
  $MBOX_RELEASE_MKDIR_PATH -- "$release"
  printf 'replacement\n' >"$source"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$source"
  printf 'old\n' >"$release/mbox"
  "$MBOX_RELEASE_CHMOD_PATH" 755 "$release/mbox"
  before=$($MBOX_RELEASE_STAT_PATH -f '%i %l %z' "$release/mbox")
  "$helper" "$source" "$release" >"$fixture/log" 2>&1 || \
    fail "atomic installer rejected an ordinary destination replacement"
  after=$($MBOX_RELEASE_STAT_PATH -f '%i %l %z' "$release/mbox")
  [[ "$before" != "$after" ]] || fail "atomic replacement reused the destination inode"
  $MBOX_RELEASE_CMP_PATH -s "$source" "$release/mbox" || fail "atomic replacement bytes differ"
  [[ "$($MBOX_RELEASE_STAT_PATH -f '%l' "$release/mbox")" == 1 ]] || fail "replacement has unexpected hard links"
  assert_no_atomic_temps "$release"

  # A second filesystem is not guaranteed on the supported host. The helper
  # still has an explicit device gate; record the available proof honestly.
  local release_device alternate_device alternate_source
  release_device=$($MBOX_RELEASE_STAT_PATH -f '%d' "$root")
  alternate_source=
  for candidate in /Volumes/*/usr/bin/true /Volumes/*/bin/sh; do
    if [[ -f "$candidate" && ! -L "$candidate" && -x "$candidate" ]]; then
      alternate_device=$($MBOX_RELEASE_STAT_PATH -f '%d' "$candidate")
      if [[ "$alternate_device" != "$release_device" ]]; then
        alternate_source="$candidate"
        break
      fi
    fi
  done
  if [[ -n "$alternate_source" ]]; then
    fixture="$root/cross-device"
    release="$fixture/release"
    $MBOX_RELEASE_MKDIR_PATH -- "$fixture"
    $MBOX_RELEASE_MKDIR_PATH -- "$release"
    "$MBOX_RELEASE_CHMOD_PATH" 755 "$release"
    if "$helper" "$alternate_source" "$release" >"$fixture/log" 2>&1; then
      fail "atomic installer accepted a cross-device source artifact"
    fi
    $MBOX_RELEASE_GREP_PATH -q 'different filesystem' "$fixture/log" || \
      fail "cross-device failure did not identify the device gate"
    assert_no_atomic_temps "$release"
    echo "macos release-check: atomic installer cross-device=REJECTED"
  else
    echo "macos release-check: atomic installer cross-device=NOT_PROVEN (no mounted second filesystem)"
  fi
}

run_clean_build() {
  local cargo_home=$1
  $MBOX_RELEASE_MKDIR_PATH -p -- "$cargo_home"
  mbox_release_recheck_tool cargo "$MBOX_RELEASE_CARGO_PATH" "$record_cargo_sha256" || return
  mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$record_rustc_sha256" || return
  mbox_release_recheck_tool linker "$MBOX_RELEASE_LINKER_PATH" "$record_linker_sha256" || return
  "$MBOX_RELEASE_ENV_PATH" -i \
    HOME=/Users/ax \
    RUSTUP_HOME=/Users/ax/.rustup \
    RUSTUP_TOOLCHAIN="$MBOX_RELEASE_TOOLCHAIN_NAME" \
    PATH="$MBOX_RELEASE_TOOLCHAIN_BIN:$MBOX_RELEASE_SYSTEM_PATH" \
    CARGO_HOME="$cargo_home" \
    CARGO_TARGET_DIR="$RESERVED_BUILD_DIR" \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS= \
    CARGO_ENCODED_RUSTFLAGS= \
    CARGO_BUILD_RUSTFLAGS= \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    CARGO_BUILD_RUSTC_WRAPPER= \
    RUSTC="$MBOX_RELEASE_RUSTC_PATH" \
    RUSTC_LINKER="$MBOX_RELEASE_LINKER_PATH" \
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$MBOX_RELEASE_LINKER_PATH" \
    CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER="$MBOX_RELEASE_LINKER_PATH" \
    SDKROOT="$MBOX_RELEASE_SDK_PATH" \
    LC_ALL=C \
    "$MBOX_RELEASE_CARGO_PATH" build --release --locked --manifest-path "$CANONICAL_REPO/Cargo.toml"
}

check_record_file() {
  local record_path=$1
  local list_file aggregate_file current_source
  make_temp_root
  list_file="$RELEASE_TMP/source-inputs.txt"
  aggregate_file="$RELEASE_TMP/source-aggregate.txt"
  current_source=$(source_fingerprint "$list_file" "$aggregate_file")
  parse_record "$record_path"
  validate_record_identity "$current_source"
  validate_compiled_helper
  validate_current_binary
  printf 'macos release-check: record check=PASS\n'
}

self_test_records() {
  local original_record_digest stale_sha sha_record source_record helper_record hostile_record hostile_log field
  original_record_digest=$(digest_for "$RECORD_FILE")
  sha_record="$RELEASE_TMP/stale-sha.record"
  source_record="$RELEASE_TMP/stale-source.record"
  helper_record="$RELEASE_TMP/stale-helper.record"
  stale_sha=0000000000000000000000000000000000000000000000000000000000000000
  $MBOX_RELEASE_SED_PATH "s/^sha256=.*/sha256=$stale_sha/" "$RECORD_FILE" > "$sha_record"
  if "$SCRIPT_PATH" --check-record "$sha_record" >"$RELEASE_TMP/stale-sha.log" 2>&1; then
    fail "self-test accepted a stale sha256 record"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'sha256 mismatch' "$RELEASE_TMP/stale-sha.log" || \
    fail "self-test stale sha256 failure did not reach the digest gate"
  $MBOX_RELEASE_SED_PATH 's/^source-fingerprint=.*/source-fingerprint=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/' \
    "$RECORD_FILE" > "$source_record"
  if "$SCRIPT_PATH" --check-record "$source_record" >"$RELEASE_TMP/stale-source.log" 2>&1; then
    fail "self-test accepted a stale source-fingerprint record"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'source fingerprint mismatch' "$RELEASE_TMP/stale-source.log" || \
    fail "self-test stale source failure did not reach the source gate"
  $MBOX_RELEASE_SED_PATH 's/^release-helper-sha256=.*/release-helper-sha256=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/' \
    "$RECORD_FILE" > "$helper_record"
  if "$SCRIPT_PATH" --check-record "$helper_record" >"$RELEASE_TMP/stale-helper.log" 2>&1; then
    fail "self-test accepted a stale release-helper-sha256 record"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'release helper source digest mismatch' "$RELEASE_TMP/stale-helper.log" || \
    fail "self-test stale helper failure did not reach the helper source gate"
  [[ "$original_record_digest" == "$(digest_for "$RECORD_FILE")" ]] || \
    fail "record self-test mutated the source-controlled record"
  echo "macos release-check: self-test stale sha256=REJECTED"
  echo "macos release-check: self-test stale source-fingerprint=REJECTED"
  echo "macos release-check: self-test stale release-helper-sha256=REJECTED"

  local cargo_path_record cargo_digest_record rustc_path_record rustc_digest_record helper_digest_record
  cargo_path_record="$RELEASE_TMP/stale-cargo-path.record"
  cargo_digest_record="$RELEASE_TMP/stale-cargo-digest.record"
  rustc_path_record="$RELEASE_TMP/stale-rustc-path.record"
  rustc_digest_record="$RELEASE_TMP/stale-rustc-digest.record"
  helper_digest_record="$RELEASE_TMP/stale-helper-binary.record"
  rewrite_record_field "$RECORD_FILE" "$cargo_path_record" cargo-path /tmp/fake-cargo
  if "$SCRIPT_PATH" --check-record "$cargo_path_record" >"$RELEASE_TMP/stale-cargo-path.log" 2>&1; then
    fail "self-test accepted an altered cargo path"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'provenance cargo path mismatch' "$RELEASE_TMP/stale-cargo-path.log" || \
    fail "self-test altered cargo path did not reach the path gate"
  rewrite_record_field "$RECORD_FILE" "$cargo_digest_record" cargo-sha256 "$stale_sha"
  if "$SCRIPT_PATH" --check-record "$cargo_digest_record" >"$RELEASE_TMP/stale-cargo-digest.log" 2>&1; then
    fail "self-test accepted an altered cargo digest"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'provenance cargo digest mismatch' "$RELEASE_TMP/stale-cargo-digest.log" || \
    fail "self-test altered cargo digest did not reach the digest gate"
  rewrite_record_field "$RECORD_FILE" "$rustc_path_record" rustc-path /tmp/fake-rustc
  if "$SCRIPT_PATH" --check-record "$rustc_path_record" >"$RELEASE_TMP/stale-rustc-path.log" 2>&1; then
    fail "self-test accepted an altered rustc path"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'provenance rustc path mismatch' "$RELEASE_TMP/stale-rustc-path.log" || \
    fail "self-test altered rustc path did not reach the path gate"
  rewrite_record_field "$RECORD_FILE" "$rustc_digest_record" rustc-sha256 "$stale_sha"
  if "$SCRIPT_PATH" --check-record "$rustc_digest_record" >"$RELEASE_TMP/stale-rustc-digest.log" 2>&1; then
    fail "self-test accepted an altered rustc digest"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'provenance rustc digest mismatch' "$RELEASE_TMP/stale-rustc-digest.log" || \
    fail "self-test altered rustc digest did not reach the digest gate"
  rewrite_record_field "$RECORD_FILE" "$helper_digest_record" release-helper-binary-sha256 "$stale_sha"
  if "$SCRIPT_PATH" --check-record "$helper_digest_record" >"$RELEASE_TMP/stale-helper-binary.log" 2>&1; then
    fail "self-test accepted an altered compiled-helper digest"
  fi
  $MBOX_RELEASE_GREP_PATH -q 'compiled release helper digest mismatch' "$RELEASE_TMP/stale-helper-binary.log" || \
    fail "self-test altered compiled-helper digest did not reach the digest gate"
  echo "macos release-check: self-test tool paths/digests and compiled-helper digest=REJECTED"

  # Every parsed value remains inert data.  Exercise all fields that have ever
  # been displayed or compared, including a host value and representative
  # path/command/toolchain values containing command substitution, backticks,
  # redirection, and separators.  The marker path is fixed by this test and
  # is never supplied to a command assembled from the record.
  local hostile_marker hostile_value
  hostile_marker="$RELEASE_TMP/hostile-record-marker"
  hostile_value='$(touch '"$hostile_marker"') `touch '"$hostile_marker"'` ; echo hostile > '"$hostile_marker"' | cat'
  for field in host rustc rustc-path rustc-sha256 cargo cargo-path cargo-sha256 \
    linker-path sdk-path hash-path hash-verify-path build-root build-path build-command verification; do
    hostile_record="$RELEASE_TMP/hostile-$field.record"
    hostile_log="$RELEASE_TMP/hostile-$field.log"
    rewrite_record_field "$RECORD_FILE" "$hostile_record" "$field" "$hostile_value"
    if "$SCRIPT_PATH" --check-record "$hostile_record" >"$hostile_log" 2>&1; then
      fail "self-test accepted hostile provenance field"
    fi
    [[ ! -e "$hostile_marker" ]] || fail "hostile provenance field caused a marker side effect"
    if $MBOX_RELEASE_GREP_PATH -Fq -- "$hostile_value" "$hostile_log"; then
      fail "hostile provenance field escaped into diagnostics"
    fi
  done
  [[ "$original_record_digest" == "$(digest_for "$RECORD_FILE")" ]] || \
    fail "hostile record self-test mutated the source-controlled record"
  echo "macos release-check: self-test hostile record fields=REJECTED without shell side effects"
  self_test_hostile_path
  self_test_startup_boundary
  if [[ -n "$ATOMIC_INSTALL_BIN" ]]; then
    atomic_install_self_test "$ATOMIC_INSTALL_BIN"
    echo "macos release-check: atomic installer adversarial fixtures=REJECTED/REPLACED"
  fi
}

rewrite_record_field() {
  local input=$1
  local output=$2
  local field=$3
  local replacement=$4
  # awk receives the replacement as data.  It is never parsed as shell source.
  $MBOX_RELEASE_AWK_PATH -v field="$field" -v replacement="$replacement" '
    index($0, field "=") == 1 { print field "=" replacement; next }
    { print }
  ' "$input" > "$output" || fail "could not construct record self-test fixture"
}

self_test_hostile_path() {
  local hostile_path="$RELEASE_TMP/hostile-path"
  local marker="$RELEASE_TMP/hostile-path-marker"
  local tool fixture
  $MBOX_RELEASE_MKDIR_PATH -- "$hostile_path"
  for tool in bash cargo rustc shasum sha256sum cmp find sed awk sort mktemp stat id; do
    fixture="$hostile_path/$tool"
    printf '#!/bin/bash\nprintf hostile-path-executed > %q\nexit 99\n' "$marker" > "$fixture"
    "$MBOX_RELEASE_CHMOD_PATH" 755 "$fixture"
  done
  PATH="$hostile_path" "$SCRIPT_PATH" --check-record "$RECORD_FILE" \
    >"$RELEASE_TMP/hostile-path.log" 2>&1 || :
  [[ ! -e "$marker" ]] || fail "hostile PATH tool was executed"
  echo "macos release-check: self-test hostile PATH tools=IGNORED without marker side effect"
}

self_test_startup_boundary() {
  local hostile_dir startup marker log nested_log
  hostile_dir="$RELEASE_TMP/hostile-startup"
  startup="$hostile_dir/startup.sh"
  marker="$hostile_dir/startup-marker"
  log="$RELEASE_TMP/hostile-startup-record.log"
  nested_log="$RELEASE_TMP/hostile-startup-nested.log"
  $MBOX_RELEASE_MKDIR_PATH -- "$hostile_dir"
  printf '#!/bin/bash\nprintf startup-injected > %q\n' "$marker" > "$startup"
  $MBOX_RELEASE_CHMOD_PATH 755 "$startup"

  # The release-check script itself must enter Bash after env(1) has dropped
  # all inherited startup controls. This covers both direct record checking
  # and a hostile PATH without relying on an in-body unset loop.
  if ! "$MBOX_RELEASE_ENV_PATH" -i \
    BASH_ENV="$startup" ENV="$startup" SHELLOPTS=errexit BASHOPTS=extdebug \
    CDPATH="$hostile_dir" GLOBIGNORE='*' BASH_XTRACEFD=9 PATH="$hostile_dir" \
    "$SCRIPT_PATH" --check-record "$RECORD_FILE" >"$log" 2>&1; then
    fail "hostile startup environment rejected a valid direct record check"
  fi
  [[ ! -e "$marker" ]] || fail "hostile startup environment reached direct release-check Bash"

  # The same hostile environment must not cross the nested verify → static →
  # contract chain. The runtime-only path is the complete native contract
  # chain without recursively entering release provenance.
  if ! "$MBOX_RELEASE_ENV_PATH" -i \
    BASH_ENV="$startup" ENV="$startup" SHELLOPTS=errexit BASHOPTS=extdebug \
    CDPATH="$hostile_dir" GLOBIGNORE='*' BASH_XTRACEFD=9 PATH="$hostile_dir" \
    "$CANONICAL_REPO/scripts/verify-macos.sh" --runtime-only >"$nested_log" 2>&1; then
    fail "hostile startup environment rejected the nested verify/static/contract chain"
  fi
  [[ ! -e "$marker" ]] || fail "hostile startup environment reached nested release Bash"
  echo "macos release-check: startup environment boundary=REJECTED hostile controls"
}

run_cargo_gate() {
  local cargo_home="$RELEASE_TMP/cargo-home-gates"
  if [[ ! -d "$cargo_home" ]]; then
    $MBOX_RELEASE_MKDIR_PATH -p -- "$cargo_home"
  fi
  mbox_release_recheck_tool cargo "$MBOX_RELEASE_CARGO_PATH" "$record_cargo_sha256" || return
  mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$record_rustc_sha256" || return
  mbox_release_recheck_tool linker "$MBOX_RELEASE_LINKER_PATH" "$record_linker_sha256" || return
  "$MBOX_RELEASE_ENV_PATH" -i \
    HOME=/Users/ax \
    RUSTUP_HOME=/Users/ax/.rustup \
    RUSTUP_TOOLCHAIN="$MBOX_RELEASE_TOOLCHAIN_NAME" \
    PATH="$MBOX_RELEASE_TOOLCHAIN_BIN:$MBOX_RELEASE_SYSTEM_PATH" \
    CARGO_HOME="$cargo_home" \
    CARGO_TARGET_DIR="$RESERVED_BUILD_DIR" \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS= \
    CARGO_ENCODED_RUSTFLAGS= \
    CARGO_BUILD_RUSTFLAGS= \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    CARGO_BUILD_RUSTC_WRAPPER= \
    RUSTC="$MBOX_RELEASE_RUSTC_PATH" \
    RUSTC_LINKER="$MBOX_RELEASE_LINKER_PATH" \
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="$MBOX_RELEASE_LINKER_PATH" \
    CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER="$MBOX_RELEASE_LINKER_PATH" \
    SDKROOT="$MBOX_RELEASE_SDK_PATH" \
    LC_ALL=C \
    "$MBOX_RELEASE_CARGO_PATH" "$@"
}

case "${1-}" in
  --check-record)
    [[ $# -eq 2 ]] || usage
    check_record_file "$2"
    exit 0
    ;;
  --self-test)
    [[ $# -eq 1 ]] || usage
    require_regular "$RECORD_FILE"
    make_temp_root
    parse_record "$RECORD_FILE"
    compile_atomic_install_helper
    validate_compiled_helper
    self_test_records
    exit 0
    ;;
  "") ;;
  *) usage ;;
esac

[[ $# -eq 0 ]] || usage
require_regular "$RECORD_FILE"
make_temp_root

SOURCE_LIST_BEFORE="$RELEASE_TMP/source-inputs-before.txt"
SOURCE_AGGREGATE_BEFORE="$RELEASE_TMP/source-aggregate-before.txt"
SOURCE_BEFORE=$(source_fingerprint "$SOURCE_LIST_BEFORE" "$SOURCE_AGGREGATE_BEFORE")
parse_record "$RECORD_FILE"
validate_record_identity "$SOURCE_BEFORE"
export MBOX_RELEASE_PROVENANCE_CARGO_SHA256="$record_cargo_sha256"
export MBOX_RELEASE_PROVENANCE_RUSTC_SHA256="$record_rustc_sha256"
export MBOX_RELEASE_PROVENANCE_RUSTFMT_SHA256="$record_rustfmt_sha256"
export MBOX_RELEASE_PROVENANCE_CLIPPY_DRIVER_SHA256="$record_clippy_driver_sha256"
export MBOX_RELEASE_PROVENANCE_LINKER_SHA256="$record_linker_sha256"

echo "macos release-check: cleaning reserved build directory $RESERVED_BUILD_DIR"
prepare_reserved_build
echo "macos release-check: clean release build one in reserved directory"
run_clean_build "$RELEASE_TMP/cargo-home-one"
FIRST_BIN="$BUILD_BIN"
require_regular "$FIRST_BIN"
[[ -x "$FIRST_BIN" ]] || fail "first canonical release binary is not executable"
FIRST_ARTIFACT="$RELEASE_TMP/mbox-first"
$MBOX_RELEASE_CP_PATH -p -- "$FIRST_BIN" "$FIRST_ARTIFACT"
require_regular "$FIRST_ARTIFACT"
FIRST_DIGEST=$(digest_for "$FIRST_ARTIFACT")

echo "macos release-check: cleaning reserved build directory before sequential rebuild"
prepare_reserved_build
echo "macos release-check: clean release build two in the same reserved directory"
run_clean_build "$RELEASE_TMP/cargo-home-two"
SECOND_BIN="$BUILD_BIN"
require_regular "$SECOND_BIN"
[[ -x "$SECOND_BIN" ]] || fail "second canonical release binary is not executable"
SECOND_DIGEST=$(digest_for "$SECOND_BIN")
$MBOX_RELEASE_CMP_PATH -s "$FIRST_ARTIFACT" "$SECOND_BIN" || \
  fail "sequential clean canonical builds differ: $FIRST_DIGEST vs $SECOND_DIGEST"
[[ "$FIRST_DIGEST" == "$SECOND_DIGEST" ]] || \
  fail "sequential clean canonical digest values differ"

SOURCE_LIST_AFTER="$RELEASE_TMP/source-inputs-after.txt"
SOURCE_AGGREGATE_AFTER="$RELEASE_TMP/source-aggregate-after.txt"
SOURCE_AFTER=$(source_fingerprint "$SOURCE_LIST_AFTER" "$SOURCE_AGGREGATE_AFTER")
[[ "$SOURCE_BEFORE" == "$SOURCE_AFTER" ]] || \
  fail "source tree changed during sequential clean release builds"
mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$record_rustc_sha256" || fail "rustc changed during release protocol"
mbox_release_recheck_tool cargo "$MBOX_RELEASE_CARGO_PATH" "$record_cargo_sha256" || fail "cargo changed during release protocol"
[[ "$RUSTC_VERSION" == "$($MBOX_RELEASE_RUSTC_PATH --version)" ]] || fail "rustc version changed during release protocol"
[[ "$CARGO_VERSION" == "$($MBOX_RELEASE_CARGO_PATH --version)" ]] || fail "cargo version changed during release protocol"
[[ "$HOST" == "$($MBOX_RELEASE_UNAME_PATH -s) $($MBOX_RELEASE_UNAME_PATH -m)" ]] || fail "host identity changed during release protocol"
[[ "$SECOND_DIGEST" == "$record_sha256" ]] || \
  fail "release sha256 record is stale"
[[ "$($SECOND_BIN --version)" == "$EXPECTED_VERSION" ]] || fail "release version mismatch"
[[ "$($SECOND_BIN --help | $MBOX_RELEASE_SED_PATH -n '1p')" == "$EXPECTED_VERSION" ]] || fail "release help version mismatch"

mbox_release_run_script "$ROOT/scripts/static-check.sh"
mbox_release_run_script "$ROOT/scripts/macos/static-check.sh"
run_cargo_gate fmt --check
run_cargo_gate check --all-targets --locked
run_cargo_gate clippy --all-targets --locked -- -D warnings
run_cargo_gate test --all-targets --locked

PROBE="$RELEASE_TMP/mbox-macos-sandbox-probe"
MBOX="$SECOND_BIN" BUILD_MBOX=0 PROBE="$PROBE" \
  mbox_release_run_script "$ROOT/tests/macos/contract.sh"

SOURCE_LIST_FINAL="$RELEASE_TMP/source-inputs-final.txt"
SOURCE_AGGREGATE_FINAL="$RELEASE_TMP/source-aggregate-final.txt"
SOURCE_FINAL=$(source_fingerprint "$SOURCE_LIST_FINAL" "$SOURCE_AGGREGATE_FINAL")
[[ "$SOURCE_BEFORE" == "$SOURCE_FINAL" ]] || \
  fail "source tree changed during release verification gates"
validate_record_identity "$SOURCE_FINAL"

# Only after both clean builds, all source/toolchain gates, and the complete
# A-AQ+AE native contract may the verified protocol artifact be installed at
# the exact AXD path. The audited native installer copies from the first
# detached artifact, not from a pre-existing ignored target/release file.
prepare_install_directory
compile_atomic_install_helper
validate_compiled_helper
mbox_release_recheck_tool rustc "$MBOX_RELEASE_RUSTC_PATH" "$record_rustc_sha256" || fail "rustc changed before helper install"
"$ATOMIC_INSTALL_BIN" "$FIRST_ARTIFACT" "$CANONICAL_RELEASE_DIR"
assert_no_symlink_components "$CANONICAL_RELEASE_DIR"
assert_owned_directory "$CANONICAL_RELEASE_DIR" "$REPO_DEVICE"
require_regular "$CANONICAL_BIN"
[[ -x "$CANONICAL_BIN" ]] || fail "installed canonical release binary is not executable"
FINAL_DIGEST=$(digest_for "$CANONICAL_BIN")
$MBOX_RELEASE_CMP_PATH -s "$FIRST_ARTIFACT" "$CANONICAL_BIN" || fail "final canonical install changed verified artifact bytes"
[[ "$FINAL_DIGEST" == "$FIRST_DIGEST" && "$FINAL_DIGEST" == "$SECOND_DIGEST" ]] || \
  fail "final canonical digest does not equal both clean build digests"
[[ "$FINAL_DIGEST" == "$record_sha256" ]] || fail "final canonical digest does not equal provenance record"
validate_current_binary
PROBE_FINAL="$RELEASE_TMP/mbox-macos-sandbox-probe-final"
MBOX="$CANONICAL_BIN" BUILD_MBOX=0 PROBE="$PROBE_FINAL" \
  mbox_release_run_script "$ROOT/tests/macos/contract.sh"
self_test_records

printf 'macos release-check: reserved build directory=%s\n' "$RESERVED_BUILD_DIR"
printf 'macos release-check: canonical target preserved=%s\n' "$CANONICAL_TARGET"
printf 'macos release-check: canonical binary=%s\n' "$CANONICAL_BIN"
printf 'macos release-check: version=%s\n' "$EXPECTED_VERSION"
printf 'macos release-check: host=%s\n' "$HOST"
printf 'macos release-check: rustc=%s\n' "$RUSTC_VERSION"
printf 'macos release-check: cargo=%s\n' "$CARGO_VERSION"
printf 'macos release-check: source-fingerprint=%s\n' "$SOURCE_BEFORE"
printf 'macos release-check: sha256=%s\n' "$FINAL_DIGEST"
printf 'macos release-check: sequential clean builds=2 at one reserved path; identical bytes\n'
printf 'macos release-check: complete contract A-AQ+AE=PASS\n'
printf 'macos release-check: fixed release protocol=PASS\n'
