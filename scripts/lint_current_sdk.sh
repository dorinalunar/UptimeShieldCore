#!/bin/sh
# Runs the official GenVM linter (genvm-lint) on contracts/UptimeShield.py.
set -e
SRC="$(dirname "$0")/../contracts/UptimeShield.py"
genvm-lint lint "$SRC"
genvm-lint check "$SRC"
genvm-lint typecheck "$SRC"
