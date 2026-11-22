#!/usr/bin/env bash
# Creates (or updates) the compineu AWS stack: one EC2 box behind CloudFront. Run from a laptop with admin-ish creds.
#   read -rs GROQ_API_KEY; export GROQ_API_KEY     # first deploy only; stored in SSM, never printed
#   AWS_PROFILE=<profile> AWS_REGION=ap-south-1 EXPECT_ACCOUNT=<account-id> bash infra/deploy.sh
# Optional env:
#   PROJECT=compineu      name prefix (resources, SSM path /$PROJECT/prod); change it to run two copies side by side
#   STACK=$PROJECT        CloudFormation stack name
#   INSTANCE_TYPE=t3a.medium   (4 GB; t3a.large for more headroom)
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
INSTANCE_TYPE="${INSTANCE_TYPE:-t3a.medium}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/compineu.yaml"
command -v cygpath >/dev/null && TEMPLATE="$(cygpath -w "$TEMPLATE")"   # Windows aws.exe needs a C:\ path

# The account id is required, so a wrong AWS_PROFILE cannot slip through.
: "${EXPECT_ACCOUNT:?set EXPECT_ACCOUNT=<12-digit account id of the account you mean to deploy to>}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
if [ "$ACCOUNT" != "$EXPECT_ACCOUNT" ]; then
  echo "wrong account: $ACCOUNT (expected $EXPECT_ACCOUNT). Check AWS_PROFILE." >&2; exit 1
fi
echo "account $ACCOUNT, region $AWS_REGION, stack $STACK, project $PROJECT"

PROJECT="$PROJECT" bash "$HERE/secrets.sh"   # the nine SSM secrets (infra/secrets.sh); existing ones are kept
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
