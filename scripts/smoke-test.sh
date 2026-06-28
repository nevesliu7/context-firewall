#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"

curl -fsS "${BASE_URL}/health" >/dev/null

curl -fsS -X POST "${BASE_URL}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "X-CFW-Tenant-Id: smoke-tenant" \
  -H "X-CFW-User-Id: smoke-user" \
  -H "X-CFW-User-Role: developer" \
  -H "X-CFW-Provider: openai" \
  -H "X-CFW-Destination: external_llm" \
  -d '{
    "model": "gpt-4.1-mini",
    "dry_run": true,
    "messages": [
      {"role": "user", "content": "Reply to jane@example.com without exposing her email."}
    ]
  }' >/dev/null

echo "smoke test passed for ${BASE_URL}"
