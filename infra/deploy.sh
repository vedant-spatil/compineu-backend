#!/usr/bin/env bash
# Creates (or updates) the PolicyGuard AWS stack in the hackathon account.
#   AWS_PROFILE=hackathon EXPECT_ACCOUNT=389070778843 bash infra/deploy.sh
#
# 1. Secrets: generated once into SSM Parameter Store as SecureStrings under /policyguard/prod/. Re-runs keep them.
#    The box reads them at deploy time and writes .env (mode 600). Nothing secret is stored in git or in the template.
# 2. Stack: infra/policyguard.yaml (CloudFront takes 10-15 minutes on first create).
#
# Teardown: aws cloudformation delete-stack --stack-name policyguard
#   The evidence bucket is kept on purpose (Object Lock, COMPLIANCE mode): empty-able only after retention ends.
#   The web and artifacts buckets must be emptied first: aws s3 rm s3://<bucket> --recursive
set -euo pipefail
export MSYS_NO_PATHCONV=1
export AWS_REGION="${AWS_REGION:-ap-south-1}" AWS_DEFAULT_REGION="${AWS_REGION:-ap-south-1}"
STACK="${STACK:-policyguard}"
PREFIX="/policyguard/prod"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/policyguard.yaml"
command -v cygpath >/dev/null && TEMPLATE="$(cygpath -w "$TEMPLATE")"   # Windows aws.exe needs a C:\ path

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
if [ -n "${EXPECT_ACCOUNT:-}" ] && [ "$ACCOUNT" != "$EXPECT_ACCOUNT" ]; then
  echo "wrong account: $ACCOUNT (expected $EXPECT_ACCOUNT). Set AWS_PROFILE=hackathon." >&2; exit 1
fi
echo "account $ACCOUNT, region $AWS_REGION, stack $STACK"

put_secret() {  # put_secret NAME VALUE  (only if absent)
  if aws ssm get-parameter --name "$PREFIX/$1" >/dev/null 2>&1; then
    echo "  secret $1: exists, kept"
  else
    aws ssm put-parameter --name "$PREFIX/$1" --type SecureString --value "$2" \
      --tags Key=Project,Value=policyguard >/dev/null
    echo "  secret $1: created"
  fi
}
rand_hex() { openssl rand -hex "$1"; }
fernet_key() { openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n'; }   # urlsafe base64 of 32 bytes

echo "== secrets ($PREFIX)"
put_secret JWT_SECRET_KEY     "$(rand_hex 48)"
put_secret PII_ENCRYPTION_KEY "$(fernet_key)"
put_secret POSTGRES_PASSWORD  "$(rand_hex 24)"
put_secret ORIGIN_SECRET      "$(rand_hex 32)"
ORIGIN_SECRET=$(aws ssm get-parameter --name "$PREFIX/ORIGIN_SECRET" --with-decryption --query Parameter.Value --output text)

echo "== network (default VPC)"
VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SUBNET=$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC" Name=availability-zone,Values="${AWS_REGION}a" \
  --query 'Subnets[0].SubnetId' --output text)
PL=$(aws ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing \
  --query 'PrefixLists[0].PrefixListId' --output text)
echo "  vpc $VPC  subnet $SUBNET  cloudfront prefix list $PL"

echo "== stack (first create waits for CloudFront: 10-15 min)"
aws cloudformation deploy \
  --stack-name "$STACK" \
  --template-file "$TEMPLATE" \
  --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset \
  --tags Project=policyguard Env=demo Team=mystical-productions \
  --parameter-overrides VpcId="$VPC" SubnetId="$SUBNET" CloudFrontPrefixList="$PL" OriginSecret="$ORIGIN_SECRET"

aws cloudformation describe-stacks --stack-name "$STACK" \
  --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
