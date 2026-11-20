#!/bin/sh
# Runs the official GenVM linter (genvm-lint) on contracts/UptimeShield.py.
#
# 1. `genvm-lint lint` on the file as written for Studio Dev.
# 2. `genvm-lint check` + `typecheck` on a copy whose header and imports are rewritten
#    to the public py-genlayer runner 1jb45aa8 shipped in GenVM v0.3.0-rc7.
set -e
SRC="$(dirname "$0")/../contracts/UptimeShield.py"
TMP="$(mktemp -d)/UptimeShield.py"
genvm-lint lint "$SRC"
sed -e 's/py-genlayer:5jycge4q8k23462jtb0b9fyey1s9qz928sz2nbrd9mg4sxqg2qng/py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6/' \
    -e 's/^import genlayer as gl$/from genlayer import */' \
    -e '/^from genlayer.types import Address$/d' -e '/^from genlayer.storage import/d' \
    -e 's/(gl.contract.Contract)/(gl.Contract)/' "$SRC" > "$TMP"
genvm-lint check "$TMP"
genvm-lint typecheck "$TMP"
