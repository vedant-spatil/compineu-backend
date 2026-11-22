#!/usr/bin/env bash
# Re-seeds the demo world on the box and resets the demo users. infra/ship.sh already seeds an EMPTY database on the first
# ship, so you only need this to load the data again (it wipes earlier demo rows, never cases, alerts or the audit trail).
#   AWS_PROFILE=hackathon AWS_REGION=<region> bash infra/bootstrap.sh [--small]
# It runs infra/box/setup.sh --reseed on the box through SSM. Passwords stay in SSM; the box reads them itself.
set -euo pipefail
. "$(dirname "$0")/demo/_stack.sh"   # sets I (instance), U (app url), PREFIX (ssm path), ADMIN_EMAIL
for a in "$@"; do
  case "$a" in --small) ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac
done
SCRIPT=$(cat <<EOS
set -euo pipefail
export PATH="\$PATH:/snap/bin" HOME=/root
test -f /opt/compineu/app/infra/box/setup.sh || { echo 'no backend on the box yet: run infra/ship.sh first'; exit 1; }
cd /opt/compineu/app
bash infra/box/setup.sh --reseed $*
EOS
)
PARAMS=$(python -c 'import json,sys; s=sys.stdin.read(); print(json.dumps({"commands": ["cat > /tmp/compineu-boot.sh <<'"'"'CMPBOOT'"'"'"] + s.splitlines() + ["CMPBOOT", "bash /tmp/compineu-boot.sh"], "executionTimeout": ["3600"]}))' <<<"$SCRIPT")
CMD=$(aws ssm send-command --instance-ids "$I" --document-name AWS-RunShellScript --comment "reseed" \
  --parameters "$PARAMS" --query Command.CommandId --output text)
echo "SSM command $CMD running on $I"
aws ssm wait command-executed --command-id "$CMD" --instance-id "$I" || true
aws ssm get-command-invocation --command-id "$CMD" --instance-id "$I" --query '[Status,StandardOutputContent,StandardErrorContent]' --output text | tail -30
echo "login: $U as $ADMIN_EMAIL; password: aws ssm get-parameter --name $PREFIX/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text"
