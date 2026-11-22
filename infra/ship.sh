#!/usr/bin/env bash
# Ships the current backend code to the box and (re)starts the stack. Runs from a laptop; no SSH:
# code goes through the artifacts bucket, commands through SSM Run Command.
#   AWS_PROFILE=hackathon AWS_REGION=<region> bash infra/ship.sh [setup options]   # working tree (tracked + new files, .gitignore applied)
# The box builds the image itself, so the slow spaCy layer stays cached between deploys. On the box, infra/box/setup.sh
# does the work: .env from SSM, images, Postgres, migrations, users, demo data (only into an empty database), health
# check. Options after the script name go to it: --small (small demo data), --reseed, --no-seed, --no-agent.
set -euo pipefail
for a in "$@"; do
  case "$a" in --small|--reseed|--no-seed|--no-agent) ;; *) echo "unknown option: $a" >&2; exit 2 ;; esac
done
SETUP_ARGS="$*"
export MSYS_NO_PATHCONV=1
export AWS_REGION="${AWS_REGION:-ap-south-1}" AWS_DEFAULT_REGION="${AWS_REGION:-ap-south-1}"
STACK="${STACK:-${PROJECT:-compineu}}"
command -v python >/dev/null || python() { python3 "$@"; }   # plain Ubuntu has python3 only
cd "$(dirname "$0")/.."   # the backend repo: docker-compose.prod.yml, docker/ and infra/ are at its root

out() { aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
BUCKET=$(out ArtifactsBucket); INSTANCE=$(out InstanceId); APP_URL=$(out AppUrl)
# Everything account- or region-specific comes from the stack outputs, so the box needs no hard-coded names.
BOXCFG="AWS_REGION=$AWS_REGION SSM_PREFIX=$(out SsmPrefix) EVIDENCE_BUCKET=$(out EvidenceBucket) LOG_GROUP=$(out LogGroup) APP_URL=$APP_URL"
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
test -f /opt/compineu/.bootstrapped || { echo 'box still bootstrapping'; exit 1; }
cd /opt/compineu
aws s3 cp s3://$BUCKET/$TARBALL /tmp/$TARBALL --only-show-errors
rm -rf app && mkdir app && tar -xzf /tmp/$TARBALL -C app   # clean tree each time: no stale files
cd app
env $BOXCFG bash infra/box/setup.sh $SETUP_ARGS
EOF
)
# Run Command executes with /bin/sh (dash); write the script to a file and run it with bash.
PARAMS=$(python -c 'import json,sys; s=sys.stdin.read(); print(json.dumps({"commands": ["cat > /tmp/compineu-ship.sh <<'"'"'CMPSHIP'"'"'"] + s.splitlines() + ["CMPSHIP", "bash /tmp/compineu-ship.sh"], "executionTimeout": ["3600"]}))' <<<"$SCRIPT")
CMD=$(aws ssm send-command --instance-ids "$INSTANCE" --document-name AWS-RunShellScript \
  --comment "ship $SHA" --parameters "$PARAMS" \
  --query Command.CommandId --output text)
echo "SSM command $CMD running on $INSTANCE (first build ~10 min for the spaCy layer)"
echo "follow: aws ssm get-command-invocation --command-id $CMD --instance-id $INSTANCE --query '[Status,StandardOutputContent]' --output text"
