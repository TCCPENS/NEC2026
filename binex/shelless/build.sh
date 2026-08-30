#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mkdir -p "$ROOT_DIR/dist"

gcc -O0 -fno-stack-protector -fno-omit-frame-pointer \
    -fPIE -pie -fcf-protection=none \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    "$ROOT_DIR/src/shelless.c" -o "$ROOT_DIR/dist/shelless"

strip --strip-all "$ROOT_DIR/dist/shelless"
libc_tmp="$ROOT_DIR/dist/.libc.so.6.tmp"
cp /lib/x86_64-linux-gnu/libc.so.6 "$libc_tmp"
mv -f "$libc_tmp" "$ROOT_DIR/dist/libc.so.6"
chmod 0555 "$ROOT_DIR/dist/shelless" "$ROOT_DIR/dist/libc.so.6"

echo "built dist/shelless and dist/libc.so.6"
