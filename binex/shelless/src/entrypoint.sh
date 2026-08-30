#!/bin/sh
set -eu

exec socat TCP-LISTEN:31337,reuseaddr,fork EXEC:/app/run-shelless,stderr
