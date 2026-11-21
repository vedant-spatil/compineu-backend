#!/usr/bin/env bash
# Ships the current backend code to the box and (re)starts the stack. Runs from a laptop; no SSH:
# code goes through the artifacts bucket, commands through SSM Run Command.
#   AWS_PROFILE=hackathon bash infra/ship.sh            # working tree (tracked + new files, .gitignore applied)
# The box builds the image itself, so the slow spaCy layer stays cached between deploys.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export AWS_REGION="${AWS_REGION:-ap-south-1}" AWS_DEFAULT_REGION="${AWS_REGION:-ap-south-1}"
STACK="${STACK:-policyguard}"
cd "$(dirname "$0")/.."

out() { aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
BUCKET=$(out ArtifactsBucket); INSTANCE=$(out InstanceId); APP_URL=$(out AppUrl)
SHA=$(git rev-parse --short HEAD)$(git diff --quiet HEAD && [ -z "$(git ls-files -o --exclude-standard)" ] || echo "-dirty-$(date +%H%M%S)")
TARBALL="backend-$SHA.tgz"
TMP="${TMPDIR:-/tmp}/$TARBALL"

# Working tree as git sees it: tracked plus new files, minus .gitignore (.env, .venv, data never leave the laptop).
git ls-files -co --exclude-standard -z | tar --null -T - -czf "$TMP"
command -v cygpath >/dev/null && TMP_AWS="$(cygpath -w "$TMP")" || TMP_AWS="$TMP"
aws s3 cp "$TMP_AWS" "s3://$BUCKET/$TARBALL" --only-show-errors
echo "uploaded $TARBALL ($(git log -1 --format=%s))"

SCRIPT=$(cat <<EOF
set -euo pipefail
export PATH="\$PATH:/snap/bin" HOME=/root
test -f /opt/policyguard/.bootstrapped || { echo 'box still bootstrapping'; exit 1; }
cd /opt/policyguard
aws s3 cp s3://$BUCKET/$TARBALL /tmp/$TARBALL --only-show-errors
rm -rf app && mkdir app && tar -xzf /tmp/$TARBALL -C app   # clean tree each time: no stale files
cd app
mkdir -p /opt/policyguard/eval && cp -u docs/eval/*.json /opt/policyguard/eval/ 2>/dev/null || true
chmod -R a+rwX /opt/policyguard/eval   # the api container runs as a non-root user and writes the live results here
bash infra/box/render-env.sh $APP_URL
docker compose -f docker-compose.prod.yml up -d --build --remove-orphans --force-recreate nginx
docker compose -f docker-compose.prod.yml up -d --remove-orphans
docker compose -f docker-compose.prod.yml ps
EOF
)
# Run Command executes with /bin/sh (dash); write the script to a file and run it with bash.
PARAMS=$(python -c 'import json,sys; s=sys.stdin.read(); print(json.dumps({"commands": ["cat > /tmp/pg-ship.sh <<'"'"'PGSHIP'"'"'"] + s.splitlines() + ["PGSHIP", "bash /tmp/pg-ship.sh"], "executionTimeout": ["3600"]}))' <<<"$SCRIPT")
CMD=$(aws ssm send-command --instance-ids "$INSTANCE" --document-name AWS-RunShellScript \
  --comment "ship $SHA" --parameters "$PARAMS" \
  --query Command.CommandId --output text)
echo "SSM command $CMD running on $INSTANCE (first build ~10 min for the spaCy layer)"
echo "follow: aws ssm get-command-invocation --command-id $CMD --instance-id $INSTANCE --query '[Status,StandardOutputContent]' --output text"
