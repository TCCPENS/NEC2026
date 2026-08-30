#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$ROOT_DIR/dist/membership"

mkdir -p "$ROOT_DIR/dist"
gcc "$ROOT_DIR/src/membership.c" \
    -std=c11 -O1 -Wall -Wextra \
    -fno-pie -no-pie -fno-stack-protector \
    -Wl,--build-id=none \
    -o "$OUT"
strip --strip-all "$OUT"
chmod 0755 "$OUT"

file "$OUT"
echo "Built: $OUT"
