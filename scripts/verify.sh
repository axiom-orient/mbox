#!/usr/bin/env -S -i PATH=/usr/bin:/bin LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-sanitized-v1 /bin/bash
set -euo pipefail

[[ ${MBOX_RELEASE_STARTUP_BOUNDARY-} == mbox-sanitized-v1 ]] || {
  printf 'verify: direct bash invocation is unsupported; use the executable path\n' >&2
  exit 69
}

ROOT=$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/.." && /bin/pwd -P)
cd "$ROOT"

case "$(/usr/bin/uname -s)" in
  Darwin) exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 /bin/bash ./scripts/verify-macos.sh "$@" ;;
  Linux) exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C MBOX_RELEASE_STARTUP_BOUNDARY=mbox-macos-sanitized-v1 /bin/bash ./scripts/verify-linux.sh "$@" ;;
  *)
    echo "verify: unsupported OS" >&2
    exit 69
    ;;
esac
