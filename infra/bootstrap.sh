#!/usr/bin/env bash
# One-time after the first ship.sh in a new account: loads the seed-42 demo world and creates the demo admin.
#   AWS_PROFILE=hackathon AWS_REGION=<region> bash infra/bootstrap.sh
# The admin password never leaves AWS: the box reads it from SSM itself. Re-running resets the demo data.
set -euo pipefail
. "$(dirname "$0")/demo/_stack.sh"   # sets I, U, PREFIX, ADMIN_EMAIL (admin@compineu.dev unless overridden)
SCRIPT=$(cat <<EOS
set -euo pipefail
export PATH="\$PATH:/snap/bin" HOME=/root
cd /opt/compineu/app
C="docker compose -f docker-compose.prod.yml"
\$C exec -T api python -m app.ingest.pg_generate --out /tmp/pg
\$C exec -T api python -m app.ingest.pg_load /tmp/pg --reset
export COMPINEU_PASSWORD=\$(aws ssm get-parameter --region $AWS_REGION --name $PREFIX/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text)
\$C exec -T -e COMPINEU_PASSWORD api python -m app.cli.create_user --email $ADMIN_EMAIL --role admin
echo bootstrap done
EOS
)
PARAMS=$(python -c 'import json,sys; s=sys.stdin.read(); print(json.dumps({"commands": ["cat > /tmp/compineu-boot.sh <<'"'"'CMPBOOT'"'"'"] + s.splitlines() + ["CMPBOOT", "bash /tmp/compineu-boot.sh"]}))' <<<"$SCRIPT")
CMD=$(aws ssm send-command --instance-ids "$I" --document-name AWS-RunShellScript --comment "bootstrap" \
  --parameters "$PARAMS" --query Command.CommandId --output text)
echo "SSM command $CMD running on $I"
aws ssm wait command-executed --command-id "$CMD" --instance-id "$I" || true
aws ssm get-command-invocation --command-id "$CMD" --instance-id "$I" --query '[Status,StandardOutputContent,StandardErrorContent]' --output text | tail -20
echo "login: $U as $ADMIN_EMAIL; password: aws ssm get-parameter --name $PREFIX/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text"
