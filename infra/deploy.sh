#!/usr/bin/env bash
# Creates (or updates) the compineu AWS stack: one EC2 box behind CloudFront. Run from a laptop with admin-ish creds.
#   read -rs GROQ_API_KEY; export GROQ_API_KEY     # first deploy only; stored in SSM, never printed
#   AWS_PROFILE=hackathon AWS_REGION=ap-south-1 EXPECT_ACCOUNT=389070778843 bash infra/deploy.sh
# Optional env:
#   PROJECT=compineu      name prefix (resources, SSM path /$PROJECT/prod); change it to run two copies side by side
#   STACK=$PROJECT        CloudFormation stack name
#   INSTANCE_TYPE=t3a.large
#   CREATE_VPC=1          build a fresh VPC even when a default VPC exists (automatic when there is none)
#   GROQ_MODEL_HEAVY / GROQ_MODEL_LIGHT   Groq model ids (defaults: openai/gpt-oss-120b and openai/gpt-oss-20b)
#   EVIDENCE_RETENTION_DAYS=1       Object Lock COMPLIANCE days (nobody can delete evidence before then)
#
# 1. Secrets: generated once into SSM Parameter Store as SecureStrings under /$PROJECT/prod/. Re-runs keep them.
#    The box reads them at deploy time and writes .env (mode 600). Nothing secret is in git or in the template.
# 2. Stack: infra/compineu.yaml (CloudFront takes 5-15 minutes on first create).
# Then: bash infra/ship.sh, bash infra/bootstrap.sh, and frontend/deploy/ship-web.sh. See infra/README.md.
#
# Teardown: bash infra/teardown.sh (empties the web and artifacts buckets, deletes the stack).
#   The evidence bucket is kept on purpose (Object Lock, COMPLIANCE mode): delete it after retention ends.
set -euo pipefail
export MSYS_NO_PATHCONV=1
export AWS_REGION="${AWS_REGION:-ap-south-1}" AWS_DEFAULT_REGION="${AWS_REGION:-ap-south-1}"
PROJECT="${PROJECT:-compineu}"
STACK="${STACK:-$PROJECT}"
PREFIX="/$PROJECT/prod"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3a.large}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/compineu.yaml"
command -v cygpath >/dev/null && TEMPLATE="$(cygpath -w "$TEMPLATE")"   # Windows aws.exe needs a C:\ path

# Deploys go to the hackathon account only. The account id is required, so a wrong AWS_PROFILE cannot slip through.
: "${EXPECT_ACCOUNT:?set EXPECT_ACCOUNT=<12-digit account id> (hackathon: 389070778843)}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
if [ "$ACCOUNT" != "$EXPECT_ACCOUNT" ]; then
  echo "wrong account: $ACCOUNT (expected $EXPECT_ACCOUNT). Check AWS_PROFILE." >&2; exit 1
fi
echo "account $ACCOUNT, region $AWS_REGION, stack $STACK, project $PROJECT"

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

echo "== secrets ($PREFIX)"
put_secret JWT_SECRET_KEY     "$(rand_hex 48)"
put_secret PII_ENCRYPTION_KEY "$(fernet_key)"
put_secret POSTGRES_PASSWORD  "$(rand_hex 24)"
put_secret ORIGIN_SECRET      "$(rand_hex 32)"
put_secret ADMIN_PASSWORD     "$(rand_hex 12)"   # demo admin login; read it with: aws ssm get-parameter --with-decryption
put_secret_from_env GROQ_API_KEY GROQ_API_KEY    # the LLM key (Groq); the box reads it from here
put_secret GROQ_MODEL_HEAVY   "${GROQ_MODEL_HEAVY:-openai/gpt-oss-120b}"
put_secret GROQ_MODEL_LIGHT   "${GROQ_MODEL_LIGHT:-openai/gpt-oss-20b}"
ORIGIN_SECRET=$(aws ssm get-parameter --name "$PREFIX/ORIGIN_SECRET" --with-decryption --query Parameter.Value --output text)

echo "== network"
# An AZ that actually offers the instance type (not every AZ has every type).
AZS=$(aws ec2 describe-instance-type-offerings --location-type availability-zone \
  --filters Name=instance-type,Values="$INSTANCE_TYPE" --query 'InstanceTypeOfferings[].Location' --output text | tr '\t' '\n' | sort)
[ -n "$AZS" ] || { echo "$INSTANCE_TYPE is not offered in $AWS_REGION; set INSTANCE_TYPE" >&2; exit 1; }
VPC="" SUBNET="" AZ=$(echo "$AZS" | head -1)
if [ -z "${CREATE_VPC:-}" ]; then
  VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
  [ "$VPC" = "None" ] && VPC=""
fi
if [ -n "$VPC" ]; then
  for Z in $AZS; do
    SUBNET=$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC" Name=availability-zone,Values="$Z" \
      Name=map-public-ip-on-launch,Values=true --query 'Subnets[0].SubnetId' --output text)
    [ "$SUBNET" != "None" ] && { AZ=$Z; break; }
    SUBNET=""
  done
  [ -n "$SUBNET" ] || { echo "  default VPC has no public subnet in an AZ offering $INSTANCE_TYPE: creating a VPC"; VPC=""; }
fi
PL=$(aws ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing \
  --query 'PrefixLists[0].PrefixListId' --output text)
echo "  vpc ${VPC:-<new>}  subnet ${SUBNET:-<new>}  az $AZ  cloudfront prefix list $PL"

echo "== stack (first create waits for CloudFront: 5-15 min)"
aws cloudformation deploy \
  --stack-name "$STACK" \
  --template-file "$TEMPLATE" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --tags Project="$PROJECT" Env=demo \
  --parameter-overrides Project="$PROJECT" InstanceType="$INSTANCE_TYPE" \
    VpcId="$VPC" SubnetId="$SUBNET" AvailabilityZone="$AZ" CloudFrontPrefixList="$PL" OriginSecret="$ORIGIN_SECRET" \
    EvidenceRetentionDays="${EVIDENCE_RETENTION_DAYS:-1}"

aws cloudformation describe-stacks --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
