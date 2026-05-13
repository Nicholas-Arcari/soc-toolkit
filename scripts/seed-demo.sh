#!/usr/bin/env bash
# Seed the running compose stack with demo data so contributors can
# capture README screenshots in a reproducible state. Pair with
# `docs/regenerating-screenshots.md` for the full workflow.
#
# Usage:
#   docker compose --profile all up -d --build
#   ./scripts/seed-demo.sh
#
# Idempotent: re-running won't double-seed the OSINT target (we skip
# creation if a "demo-example-com" target already exists). The SOC
# toolkit is stateless, so its seed just exercises the pipelines once
# to warm the cache.

set -euo pipefail

SOC_API="${SOC_API:-http://localhost:8000/api}"
OSINT_API="${OSINT_API:-http://localhost:8001/api}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOC_SAMPLES="$REPO_ROOT/packages/soc-toolkit/samples"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: $1 is required but not on PATH" >&2
    exit 1
  }
}
need curl
need jq

echo "==> waiting for SOC backend ($SOC_API/health)"
for _ in $(seq 1 30); do
  curl -fsS "$SOC_API/health" >/dev/null 2>&1 && break
  sleep 2
done

echo "==> waiting for OSINT backend ($OSINT_API/health)"
for _ in $(seq 1 30); do
  curl -fsS "$OSINT_API/health" >/dev/null 2>&1 && break
  sleep 2
done

echo "==> SOC: analyze bundled phishing sample"
curl -fsS -X POST "$SOC_API/phishing/analyze" \
  -F "file=@$SOC_SAMPLES/emails/phishing_sample.eml" \
  | jq '{verdict, risk_score, indicators: (.indicators | length)}'

echo "==> SOC: analyze bundled auth.log"
curl -fsS -X POST "$SOC_API/logs/analyze" \
  -F "file=@$SOC_SAMPLES/logs/auth.log" \
  -F "log_type=ssh" \
  | jq '{alerts: (.alerts | length), summary}'

echo "==> SOC: extract IOCs from threat report"
curl -fsS -X POST "$SOC_API/ioc/extract" \
  -F "file=@$SOC_SAMPLES/reports/threat_report_sample.txt" \
  | jq '{total: (.iocs | length), by_type: (.iocs | group_by(.type) | map({type: .[0].type, count: length}))}'

echo "==> OSINT: ensure demo target exists"
existing=$(
  curl -fsS "$OSINT_API/targets" \
    | jq -r '.[] | select(.name == "demo-example-com") | .id' \
    | head -n1 || true
)
if [[ -n "$existing" ]]; then
  target_id="$existing"
  echo "    reusing target id=$target_id"
else
  target_id=$(
    curl -fsS -X POST "$OSINT_API/targets" \
      -H 'Content-Type: application/json' \
      -d '{"name":"demo-example-com","owner_email":"demo@example.com","scope_domains":["example.com"],"authorized_to_scan":true}' \
      | jq -r '.id'
  )
  echo "    created target id=$target_id"
fi

echo "==> OSINT: run passive subdomain enumeration on demo target"
curl -fsS -X POST "$OSINT_API/scans/targets/$target_id/subdomain-enum" \
  | jq '{status, summary}'

echo
echo "Demo data seeded."
echo "  SOC frontend:   http://localhost:3000"
echo "  OSINT frontend: http://localhost:3001 (open target '$target_id' to see results)"
