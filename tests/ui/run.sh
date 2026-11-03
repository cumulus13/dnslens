#!/usr/bin/env bash

# File: ui/run.sh
# Author: Hadi Cahyadi <cumulus13@gmail.com>
# Date: 2026-11-03 07:32:00 SE Asia Standard Time
# Description:
# License: GPL-3.0

# Smoke-tests the web UI in jsdom against a real dnslens stack. Needs: python deps installed, node 18+, `npm i` in this dir.
set -euo pipefail
cd "$(dirname "$0")"
python stack.py > stack.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
for _ in $(seq 1 40); do grep -q READY stack.log 2>/dev/null && break; sleep 0.5; done
grep -q READY stack.log || { cat stack.log; echo "stack did not start"; exit 1; }
echo '=== live via Server-Sent Events ==='
node ui_smoke.mjs
echo '=== live via polling fallback ==='
UI_NO_SSE=1 node ui_smoke.mjs
