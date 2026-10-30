#!/usr/bin/env bash
# Runs one CI step. If it fails, the last 40 lines of its output also go into an error annotation,
# which shows on the run page (and in the API) without downloading the full log.
set -o pipefail
log="$(mktemp)"
"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
  message="$(tail -n 40 "$log" | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/%/%25/g' -e 's/\r//g' | awk '{printf "%s%%0A", $0}')"
  echo "::error title=Failed: $*::${message}"
fi
exit "$status"
