#!/usr/bin/env bash
# Independent WAF benchmark: runs GoTestWAF (Wallarm, open source) against the edge.
#
#   tools/gotestwaf.sh [URL]          default URL: https://localhost:8440/
#
# GoTestWAF sends a few thousand attack payloads (OWASP and community sets, with encodings and in
# different places: URL, headers, JSON, forms...) plus legitimate requests that look suspicious
# (false-positive set). Reports: reports/gotestwaf.json and reports/gotestwaf.html.
# Needs Go and git. Built from a pinned tag rather than pulled as a moving "latest" image.
set -euo pipefail

VERSION="${GOTESTWAF_VERSION:-v0.5.11}"
# Extra options for the summary, for example GOTESTWAF_SUMMARY="--details --min-blocked 80"
read -r -a SUMMARY_ARGS <<< "${GOTESTWAF_SUMMARY:-}"
URL="${1:-https://localhost:8440/}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/.cache/gotestwaf-$VERSION"

if [ ! -x "$SRC/gotestwaf" ]; then
  rm -rf "$SRC"
  git clone --quiet --depth 1 --branch "$VERSION" https://github.com/wallarm/gotestwaf "$SRC"
  (cd "$SRC" && go build -o gotestwaf ./cmd/gotestwaf)
fi

mkdir -p "$ROOT/reports"
cd "$SRC"  # GoTestWAF reads its payloads from ./testcases
# 403 = blocked by the WAF. 200/404/405 = reached the origin (405: POST on a static page).
# 415 is left out on purpose: GoTestWAF counts it as "unresolved" instead of hiding it in either side.
./gotestwaf \
  --url "$URL" \
  --skipWAFIdentification \
  --noEmailReport \
  --blockStatusCodes 403 \
  --passStatusCodes 200,404,405 \
  --workers 4 \
  --reportPath "$ROOT/reports" \
  --reportName gotestwaf \
  --reportFormat json,html

python3 "$ROOT/tools/gotestwaf_summary.py" "$ROOT/reports/gotestwaf.json" "${SUMMARY_ARGS[@]}"
