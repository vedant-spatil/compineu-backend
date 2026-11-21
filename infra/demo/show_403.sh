#!/usr/bin/env bash
# Live-demo helper: call the mock agent portal AS an agent and show the HTTP status in big letters.
# Run it once BEFORE approving (expect 200: he can still read) and once AFTER approving PB1 (expect 403).
#   AWS_PROFILE=hackathon bash infra/demo/show_403.sh [AGENT_ID] [POLICYHOLDER_ID]
# Defaults: AG-1147 and PH-00001. A refused call is recorded as a denied access event, which is the point.
export AWS_REGION=ap-south-1 MSYS_NO_PATHCONV=1
AGENT=${1:-AG-1147}; PH=${2:-PH-00001}
U=https://d2qe22rm1i2e6w.cloudfront.net
PW=$(aws ssm get-parameter --name /policyguard/prod/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text)
TOK=$(curl -s -X POST "$U/api/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"ciso@policyguard.demo\",\"password\":\"$PW\"}" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'); unset PW
OUT=$(curl -s -w '\n%{http_code}' -H "Authorization: Bearer $TOK" -H "X-Agent-Id: $AGENT" \
  -H "X-Device-Id: dv-9f2c" -H "X-Client-City: Lucknow" "$U/api/portal/policyholders/$PH"); unset TOK
CODE=$(echo "$OUT" | tail -1); BODY=$(echo "$OUT" | sed '$d')
echo
echo "  $AGENT  ->  GET /api/portal/policyholders/$PH"
if [ "$CODE" = "403" ]; then
  printf '  \033[1;31mHTTP %s  REFUSED\033[0m   %s\n' "$CODE" "$(echo "$BODY" | python -c 'import sys,json; d=json.load(sys.stdin)["detail"]; print(d["error"])' 2>/dev/null)"
elif [ "$CODE" = "200" ]; then
  printf '  \033[1;32mHTTP %s  allowed\033[0m   (the record was opened and logged)\n' "$CODE"
else
  printf '  HTTP %s  %s\n' "$CODE" "$(echo "$BODY" | head -c 160)"
fi
echo
