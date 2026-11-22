#!/usr/bin/env bash
# compineu box setup. Runs ON THE EC2 BOX, inside the unpacked backend folder (/opt/compineu/app), after the backend
# tarball was pulled from the artifacts bucket. One command does everything:
#   1. writes .env from SSM Parameter Store (mode 600)
#   2. builds the Docker images and starts Postgres
#   3. starts the API (it runs the Alembic migrations on start) and nginx
#   4. creates the users (admin and qa) with passwords read from SSM
#   5. seeds the synthetic demo data (only when the database is empty)
#   6. installs the CloudWatch agent for host metrics
#   7. checks health and prints a summary
#
#   sudo bash infra/box/setup.sh [--no-seed] [--reseed] [--small] [--no-agent]
#     --no-seed    users and containers only, no demo data
#     --reseed     wipe the earlier demo data (never cases, alerts or the audit trail) and load it again
#     --small      load the small fixture (scenario actors, 7 days) instead of the full 50,000-policyholder world;
#                  use it on a t3a.small or when you want a fast start
#     --no-agent   skip the CloudWatch agent
#
# Safe to run again: it rebuilds, recreates containers, resets user passwords to the SSM values, and seeds only an
# empty database. Non-secret names come from /opt/compineu/box.env (written on the first run and by infra/ship.sh) or
# from the environment, which wins:
#   AWS_REGION  SSM_PREFIX  EVIDENCE_BUCKET  LOG_GROUP  APP_URL
# Secrets only ever come from SSM. Nothing secret is printed. DRY_RUN=1 prints the steps without running them.
set -euo pipefail

NO_SEED="" RESEED="" SMALL="" NO_AGENT=""
for arg in "$@"; do
  case "$arg" in
    --no-seed) NO_SEED=1 ;;
    --reseed) RESEED=1 ;;
    --small) SMALL=1 ;;
    --no-agent) NO_AGENT=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done
[ -n "$NO_SEED" ] && [ -n "$RESEED" ] && { echo "--no-seed and --reseed cannot be combined" >&2; exit 2; }

# Options are valid: now become root (docker, /opt/compineu). Not in a dry run.
if [ "$(id -u)" -ne 0 ] && [ -z "${DRY_RUN:-}" ]; then
  exec sudo -E env "PATH=$PATH:/snap/bin" bash "$0" "$@"
fi
export PATH="$PATH:/snap/bin" HOME="${HOME:-/root}"

cd "$(dirname "$0")/../.."
[ -f docker-compose.prod.yml ] || { echo "run this from the unpacked backend folder (docker-compose.prod.yml not found)" >&2; exit 1; }

# ---- non-secret names: environment first, then /opt/compineu/box.env, then defaults
BOXENV="${BOXENV:-/opt/compineu/box.env}"
for v in AWS_REGION SSM_PREFIX EVIDENCE_BUCKET LOG_GROUP APP_URL; do
  eval "_env_$v=\${$v:-}"
done
if [ -f "$BOXENV" ]; then . "$BOXENV"; fi
for v in AWS_REGION SSM_PREFIX EVIDENCE_BUCKET LOG_GROUP APP_URL; do
  eval "_e=\$_env_$v"; [ -n "$_e" ] && eval "$v=\$_e"
done
AWS_REGION="${AWS_REGION:-ap-south-1}"
SSM_PREFIX="${SSM_PREFIX:-/compineu/prod}"
LOG_GROUP="${LOG_GROUP:-$SSM_PREFIX}"
: "${EVIDENCE_BUCKET:?EVIDENCE_BUCKET is not set. Export it, or run infra/ship.sh once (it writes $BOXENV)}"
: "${APP_URL:?APP_URL is not set (the CloudFront https URL). Export it, or run infra/ship.sh once}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@compineu.dev}"
QA_EMAIL="${QA_EMAIL:-qa@compineu.dev}"
export AWS_REGION SSM_PREFIX EVIDENCE_BUCKET LOG_GROUP

run() { if [ -n "${DRY_RUN:-}" ]; then echo "[dry-run] $*"; else "$@"; fi; }
step() { printf '\n== %s\n' "$*"; }
dc() { docker compose -f docker-compose.prod.yml "$@"; }
ssm_get() {
  if [ -n "${DRY_RUN:-}" ]; then echo "<dry-run>"; return 0; fi
  aws ssm get-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/$1" --with-decryption \
    --query Parameter.Value --output text 2>/dev/null
}

wait_for() {  # wait_for LABEL SECONDS COMMAND...   fails with the service log when the time runs out
  local label="$1" secs="$2"; shift 2
  [ -n "${DRY_RUN:-}" ] && { echo "[dry-run] wait for $label"; return 0; }
  local end=$(( $(date +%s) + secs ))
  until "$@" >/dev/null 2>&1; do
    if [ "$(date +%s)" -ge "$end" ]; then
      echo "timed out after ${secs}s waiting for $label. Last log lines:" >&2
      dc logs --tail 30 2>&1 | tail -30 >&2 || true
      exit 1
    fi
    sleep 3
  done
  echo "  $label ready"
}
pg_ready() { dc exec -T postgres pg_isready -U compineu -d compineu -q; }
api_healthy() { [ "$(docker inspect -f '{{.State.Health.Status}}' "$(dc ps -q api)" 2>/dev/null)" = healthy ]; }
psql_q() { dc exec -T postgres psql -U compineu -d compineu -Atc "$1" | tr -d '\r'; }

echo "compineu box setup: region $AWS_REGION, ssm $SSM_PREFIX, log group $LOG_GROUP, bucket $EVIDENCE_BUCKET"
run mkdir -p /opt/compineu
if [ -z "${DRY_RUN:-}" ]; then
  umask 022
  cat > "$BOXENV" <<EOF
# Non-secret names for infra/box/setup.sh. Written by setup.sh. No secrets here.
AWS_REGION=$AWS_REGION
SSM_PREFIX=$SSM_PREFIX
EVIDENCE_BUCKET=$EVIDENCE_BUCKET
LOG_GROUP=$LOG_GROUP
APP_URL=$APP_URL
EOF
fi

step "1/7 .env from SSM ($SSM_PREFIX)"
run bash infra/box/render-env.sh "$APP_URL"
run mkdir -p /opt/compineu/eval
if [ -z "${DRY_RUN:-}" ]; then
  cp -u docs/eval/*.json /opt/compineu/eval/ 2>/dev/null || true
  chmod -R a+rwX /opt/compineu/eval   # the api container runs as a non-root user and writes live results here
fi

step "2/7 Docker images and Postgres (the first build takes about 10 minutes: the spaCy model layer)"
run dc build
run dc up -d postgres
wait_for "Postgres" 180 pg_ready

step "3/7 API (runs 'alembic upgrade head' on start) and nginx"
run dc up -d --remove-orphans --force-recreate nginx   # nginx waits for a healthy api
run dc up -d --remove-orphans
wait_for "API health check" 240 api_healthy
run dc ps

step "4/7 users"
create_user() {  # create_user EMAIL ROLE SSM_NAME
  local pw
  pw=$(ssm_get "$3") || pw=""
  if [ -z "$pw" ] && [ -z "${DRY_RUN:-}" ]; then
    echo "  skipped $1: no SSM parameter $SSM_PREFIX/$3 (run infra/deploy.sh to create it)"; return 0
  fi
  COMPINEU_PASSWORD="$pw" run dc exec -T -e COMPINEU_PASSWORD api python -m app.cli.create_user --email "$1" --role "$2"
}
create_user "$ADMIN_EMAIL" admin ADMIN_PASSWORD
create_user "$QA_EMAIL" qa QA_PASSWORD

step "5/7 demo data"
if [ -n "$NO_SEED" ]; then
  echo "  skipped (--no-seed)"
else
  HAVE=0
  [ -z "${DRY_RUN:-}" ] && HAVE=$(psql_q "select count(*) from parties where account_id like 'PH-%'")
  if [ "${HAVE:-0}" -gt 0 ] && [ -z "$RESEED" ]; then
    echo "  $HAVE policyholders already loaded: skipped (use --reseed to load again)"
  else
    if [ -n "$SMALL" ]; then GEN="--fixture"; else GEN="--out"; fi
    run dc exec -T api python -m app.ingest.pg_generate "$GEN" /tmp/pg
    run dc exec -T api python -m app.ingest.pg_load /tmp/pg --reset
  fi
fi

step "6/7 CloudWatch agent (host metrics, namespace compineu/EC2)"
if [ -n "$NO_AGENT" ]; then
  echo "  skipped (--no-agent)"
elif [ -n "${DRY_RUN:-}" ]; then
  echo "[dry-run] bash scripts/aws/03-cw-agent.sh"
else
  bash scripts/aws/03-cw-agent.sh || echo "  warning: the CloudWatch agent did not install; the app is fine. Run scripts/aws/03-cw-agent.sh again later."
fi

step "7/7 check"
if [ -n "${DRY_RUN:-}" ]; then
  echo "[dry-run] health and row counts"
else
  dc exec -T api python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=5).read().decode())"
  for q in "users|select count(*) from users" "policyholders|select count(*) from parties where account_id like 'PH-%'" \
           "agents|select count(*) from agents" "access events|select count(*) from access_events"; do
    printf '  %-14s %s\n' "${q%%|*}" "$(psql_q "${q#*|}")"
  done
fi

cat <<EOF

done.
  app            $APP_URL
  admin login    $ADMIN_EMAIL
  qa login       $QA_EMAIL
  passwords      aws ssm get-parameter --name $SSM_PREFIX/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text
                 (and QA_PASSWORD for the qa user)
  logs           CloudWatch log group $LOG_GROUP
  evidence       s3://$EVIDENCE_BUCKET (Object Lock, COMPLIANCE)
EOF
