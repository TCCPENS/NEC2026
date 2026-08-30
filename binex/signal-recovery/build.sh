#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$root_dir/dist"

gcc \
  -O0 \
  -fno-stack-protector \
  -fno-pie \
  -no-pie \
  -fcf-protection=none \
  -Wl,-z,relro,-z,noexecstack \
  -Wall -Wextra \
  "$root_dir/src/recovery.c" \
  -o "$root_dir/dist/signal_recovery"

# Keep dynamic imports useful for analysis, but remove source and local symbols.
strip --strip-all "$root_dir/dist/signal_recovery"
chmod 0555 "$root_dir/dist/signal_recovery"

echo "built: $root_dir/dist/signal_recovery"
