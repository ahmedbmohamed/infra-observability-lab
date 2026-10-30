#!/usr/bin/env bash
# Publishes a text file as GitHub notice annotations, in chunks small enough not to be cut
# (annotations are readable from the API, unlike artifacts and logs in some environments).
#   tools/ci-notice.sh FILE TITLE
set -euo pipefail
file="$1"; title="$2"; part=1; chunk=""
flush() {
  [ -z "$chunk" ] && return
  echo "::notice title=${title} (${part})::${chunk}"
  part=$((part + 1)); chunk=""
}
while IFS= read -r line || [ -n "$line" ]; do
  line="${line//%/%25}"
  if [ $(( ${#chunk} + ${#line} )) -gt 3500 ]; then flush; fi
  chunk+="${line}%0A"
done < "$file"
flush
