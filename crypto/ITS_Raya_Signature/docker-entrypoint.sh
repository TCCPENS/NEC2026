#!/bin/sh
set -eu

exec socat TCP4-LISTEN:9999,fork,reuseaddr EXEC:'python -u /app/chall.py',pty,stderr
