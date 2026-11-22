#!/usr/bin/env bash
# Creates the compineu secrets in SSM Parameter Store as SecureStrings under /$PROJECT/prod/. Existing ones are kept, so
# it is safe to run again. infra/deploy.sh runs this too; run it alone when you build the AWS resources by hand
# (see infra/MANUAL-SETUP.md).
#   read -rs GROQ_API_KEY; export GROQ_API_KEY       # typed, not echoed; needed only while the parameter is missing
#   AWS_PROFILE=<profile> AWS_REGION=ap-south-1 EXPECT_ACCOUNT=<12-digit account id> bash infra/secrets.sh
# Optional env: PROJECT (default compineu), GROQ_MODEL_HEAVY, GROQ_MODEL_LIGHT.
# Created: JWT_SECRET_KEY, PII_ENCRYPTION_KEY, POSTGRES_PASSWORD, ORIGIN_SECRET, ADMIN_PASSWORD, QA_PASSWORD, GROQ_API_KEY,
# GROQ_MODEL_HEAVY, GROQ_MODEL_LIGHT. No value is ever printed.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export AWS_REGION="${AWS_REGION:-ap-south-1}" AWS_DEFAULT_REGION="${AWS_REGION:-ap-south-1}"
PROJECT="${PROJECT:-compineu}"
PREFIX="/$PROJECT/prod"

# The account id is required, so a wrong AWS_PROFILE cannot slip through.
: "${EXPECT_ACCOUNT:?set EXPECT_ACCOUNT=<12-digit account id of the account you mean to use>}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
if [ "$ACCOUNT" != "$EXPECT_ACCOUNT" ]; then
  echo "wrong account: $ACCOUNT (expected $EXPECT_ACCOUNT). Check AWS_PROFILE." >&2; exit 1
fi

put_secret() {  # put_secret NAME VALUE  (only if absent)
  if aws ssm get-parameter --name "$PREFIX/$1" >/dev/null 2>&1; then
    echo "  secret $1: exists, kept"
  else
    aws ssm put-parameter --name "$PREFIX/$1" --type SecureString --value "$2" \
      --tags Key=Project,Value="$PROJECT" >/dev/null
    echo "  secret $1: created"
  fi
}
put_secret_from_env() {  # put_secret_from_env NAME ENVVAR  (value comes from your shell; needed only while absent)
  if aws ssm get-parameter --name "$PREFIX/$1" >/dev/null 2>&1; then
    echo "  secret $1: exists, kept"
  elif [ -z "${!2:-}" ]; then
    echo "  secret $1 is missing in SSM: export $2 and run again (the value is never printed)" >&2; exit 1
  else
    put_secret "$1" "${!2}"
  fi
}
rand_hex() { openssl rand -hex "$1"; }
fernet_key() { openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; }   # urlsafe base64 of 32 bytes

echo "== secrets ($PREFIX, account $ACCOUNT, region $AWS_REGION)"
put_secret JWT_SECRET_KEY     "$(rand_hex 48)"
put_secret PII_ENCRYPTION_KEY "$(fernet_key)"
put_secret POSTGRES_PASSWORD  "$(rand_hex 24)"
put_secret ORIGIN_SECRET      "$(rand_hex 32)"   # CloudFront sends it as X-Origin-Verify; nginx on the box checks it
put_secret ADMIN_PASSWORD     "$(rand_hex 12)"   # demo admin login; read it with: aws ssm get-parameter --with-decryption
put_secret QA_PASSWORD        "$(rand_hex 12)"   # demo qa reviewer login (admin assigns cases to it), created by infra/box/setup.sh
put_secret_from_env GROQ_API_KEY GROQ_API_KEY    # the LLM key (Groq); the box reads it from here
put_secret GROQ_MODEL_HEAVY   "${GROQ_MODEL_HEAVY:-openai/gpt-oss-120b}"
put_secret GROQ_MODEL_LIGHT   "${GROQ_MODEL_LIGHT:-openai/gpt-oss-20b}"
echo "done. Read a password with: aws ssm get-parameter --name $PREFIX/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text"
