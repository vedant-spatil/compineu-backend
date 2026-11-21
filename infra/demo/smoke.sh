#!/usr/bin/env bash
# Replay one scenario on AWS, wait for it and for the case to settle, and print what happened.
#   AWS_PROFILE=hackathon bash infra/demo/smoke.sh S1b [more scenarios...]   (resets first)
export AWS_REGION=ap-south-1 MSYS_NO_PATHCONV=1
I=i-00b4b7aecc2e25e69; U=https://d2qe22rm1i2e6w.cloudfront.net
q() { local P; P=$(python -c 'import json,sys; q=sys.argv[1]; print(json.dumps({"commands":["cd /opt/policyguard/app && docker compose -f docker-compose.prod.yml exec -T postgres psql -U policyguard -d policyguard -Atc \"%s\"" % q.replace(chr(34), chr(92)+chr(34))]}))' "$1"); local C; C=$(aws ssm send-command --instance-ids $I --document-name AWS-RunShellScript --parameters "$P" --query Command.CommandId --output text); sleep 4; aws ssm get-command-invocation --command-id $C --instance-id $I --query StandardOutputContent --output text; }
PW=$(aws ssm get-parameter --name /policyguard/prod/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text)
TOK=$(curl -s -X POST "$U/api/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"ciso@policyguard.demo\",\"password\":\"$PW\"}" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'); unset PW
A=(-H "Authorization: Bearer $TOK")
for SID in "$@"; do
  curl -s -X POST "${A[@]}" $U/api/replay/reset >/dev/null
  echo "=== $SID: $(curl -s -X POST "${A[@]}" "$U/api/replay/$SID?speed=60" | python -c 'import sys,json; d=json.load(sys.stdin); print(d.get("state"), d.get("events"), "events,", d.get("real_duration_s"), "s, expected:", d.get("expected_route"))')"
  for i in $(seq 1 30); do sleep 4; S=$(curl -s "${A[@]}" $U/api/replay/status | python -c "import sys,json; r=json.load(sys.stdin)['runs']['$SID']; print(r['state'])"); [ "$S" = "done" ] || [ "$S" = "error" ] && break; done
  # let the workflow finish (model calls)
  for i in $(seq 1 24); do sleep 5; ST=$(q "select status from cases order by id desc limit 1" | tr -d '\r\n '); case "$ST" in awaiting_review|auto_resolved|failed|closed) break;; esac; done
  echo "replay: $S; case status: ${ST:-none}"
  q "select c.id, c.status, c.account_id, round(c.risk_score::numeric,3), a.rules::text from cases c join alerts a on a.id=c.alert_id order by c.id desc limit 1"
  q "select node||'/'||kind||' x'||count(*) from case_events where case_id=(select max(id) from cases) group by node, kind order by min(id)" | tr '\n' ' '; echo
  q "select 'route: '||left(payload_json::text,230) from case_events where case_id=(select max(id) from cases) and node='route' order by id desc limit 1"
  q "select 'errors: '||left(payload_json::text,200) from case_events where case_id=(select max(id) from cases) and kind='error' limit 3"
  q "select 'report v'||version||': '||left(body_redacted::text,60) from sar_drafts where case_id=(select max(id) from cases) order by version desc limit 1"
  q "select 'justification: '||(body_redacted->'justification')::text from sar_drafts where case_id=(select max(id) from cases) order by version desc limit 1" | cut -c1-420
done
curl -s -X POST "${A[@]}" $U/api/replay/reset >/dev/null; unset TOK
