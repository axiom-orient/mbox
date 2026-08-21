#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$ROOT"

case "$(uname -s)" in
  Darwin) exec ./scripts/verify-macos.sh "$@" ;;
  Linux) exec ./scripts/verify-linux.sh "$@" ;;
  *)
    echo "verify: unsupported OS" >&2
    exit 69
    ;;
esac
