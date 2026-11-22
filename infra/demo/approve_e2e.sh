#!/usr/bin/env bash
# End-to-end: replay a scenario, approve its incident with playbooks, then prove the containment and the evidence.
#   AWS_PROFILE=<profile> bash infra/demo/approve_e2e.sh S1 PB1,PB6,PB7 AG-1147    (or: S2 PB2,PB6,PB7 PK-CARELINK)
. "$(dirname "$0")/_stack.sh"
SID=${1:-S1}; PBS=${2:-PB1,PB6,PB7}; ACTOR=${3:-AG-1147}
q() { local P; P=$(python -c 'import json,sys; q=sys.argv[1]; print(json.dumps({"commands":["cd /opt/compineu/app && docker compose -f docker-compose.prod.yml exec -T postgres psql -U compineu -d compineu -Atc \"%s\"" % q.replace(chr(34), chr(92)+chr(34))]}))' "$1"); local C; C=$(aws ssm send-command --instance-ids $I --document-name AWS-RunShellScript --parameters "$P" --query Command.CommandId --output text); sleep 4; aws ssm get-command-invocation --command-id $C --instance-id $I --query StandardOutputContent --output text; }
PW=$(aws ssm get-parameter --name $PREFIX/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text)
TOK=$(curl -s -X POST "$U/api/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$PW\"}" | python -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'); unset PW
A=(-H "Authorization: Bearer $TOK")
curl -s -X POST "${A[@]}" $U/api/replay/reset >/dev/null
curl -s -X POST "${A[@]}" "$U/api/replay/$SID?speed=60" >/dev/null
for i in $(seq 1 30); do sleep 4; S=$(curl -s "${A[@]}" $U/api/replay/status | python -c "import sys,json; print(json.load(sys.stdin)['runs']['$SID']['state'])"); [ "$S" = "done" ] && break; done
for i in $(seq 1 30); do sleep 5; ST=$(q "select status from cases order by id desc limit 1" | tr -d '\r\n '); [ "$ST" = "awaiting_review" ] && break; done
CASE=$(q "select max(id) from cases" | tr -d '\r\n '); echo "scenario $SID replayed; case $CASE is $ST"
PB_JSON=$(python -c "print(__import__('json').dumps('$PBS'.split(',')))")
echo "== approve with $PBS"
RESP=$(curl -s -X POST "${A[@]}" -H 'Content-Type: application/json' "$U/api/cases/$CASE/decision" -w ' [%{http_code}]' \
  -d "{\"action\":\"approve\",\"reason\":\"Reviewed the evidence: out-of-scope bulk access confirmed, containing now.\",\"reviewed\":true,\"playbooks\":$PB_JSON}")
echo "$RESP" | cut -c1-200
sleep 8
echo "== case status + decision"; q "select c.status, d.action, d.playbooks::text from cases c join decisions d on d.case_id=c.id where c.id=$CASE"
echo "== playbook audit events"; q "select kind, left(payload_json::text, 200) from case_events where case_id=$CASE and node='playbook' order by id"
echo "== containment proof"
if [ "${ACTOR#PK-}" = "$ACTOR" ]; then
  PH=$(q "select policyholder_id from portfolios where agent_id<>'$ACTOR' limit 1" | tr -d '\r\n ')
  echo "agent $ACTOR credential_enabled: $(q "select credential_enabled from agents where agent_id='$ACTOR'" | tr -d '\r\n ')"
  echo "portal view as $ACTOR after approval: $(curl -s "${A[@]}" -H "X-Agent-Id: $ACTOR" $U/api/portal/policyholders/$PH -w ' [%{http_code}]' | head -c 140)"
else
  CL=$(q "select claim_id from partner_claim_assignments limit 1" | tr -d '\r\n ')
  echo "key $ACTOR enabled: $(q "select enabled from partner_keys where key_id='$ACTOR'" | tr -d '\r\n ')"
  echo "partner call as $ACTOR after approval: $(curl -s "${A[@]}" -H "X-Api-Key: $ACTOR" $U/api/partner/claims/$CL -w ' [%{http_code}]' | head -c 140)"
fi
echo "== evidence in S3 (Object Lock)"
KEY=$(q "select payload_json->>'key' from case_events where case_id=$CASE and kind='PB6_evidence_preserved' order by id desc limit 1" | tr -d '\r\n ')
echo "key: $KEY"
[ -n "$KEY" ] && aws s3api head-object --bucket $BUCKET --key "$KEY" --query '{bytes:ContentLength,lock:ObjectLockMode,until:ObjectLockRetainUntilDate}' --output json
echo "== notification"; q "select kind, left(message,110) from notifications where kind='incident_actioned' order by id desc limit 1"
curl -s -X POST "${A[@]}" $U/api/replay/reset >/dev/null; unset TOK
echo "== after reset: agent restored: $(q "select credential_enabled from agents where agent_id='$ACTOR'" | tr -d '\r\n ')"
