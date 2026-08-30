#!/bin/sh
set -eu

# Keep the organizer-supplied libc scoped to the challenge process. In
# particular, socat itself must continue using the container's libc.
exec /lib64/ld-linux-x86-64.so.2 --library-path /app /app/shelless
