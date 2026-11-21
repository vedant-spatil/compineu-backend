#!/usr/bin/env bash
# PolicyGuard preflight: confirms WHICH account we are on and what the sandbox lets us do.
# Read-only apart from one tiny Bedrock Converse call per model (fractions of a cent).
#   AWS_PROFILE=hackathon scripts/aws/00-preflight.sh
# Optional: EXPECT_ACCOUNT=123456789012 to fail fast if the wrong credentials are active.
set -uo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows otherwise rewrites /aws/service/... SSM paths

REGION="${AWS_REGION:-ap-south-1}"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
# Models in use: Sonnet 4.6 (global profile) for heavy calls, Haiku 4.5 (India profile) for light calls.
# The 5.5 models are not enabled for the hackathon account. Override with LLM_MODEL_HEAVY / LLM_MODEL_LIGHT to test others.
HEAVY="${LLM_MODEL_HEAVY:-global.anthropic.claude-sonnet-4-6}"
LIGHT="${LLM_MODEL_LIGHT:-in.anthropic.claude-haiku-4-5-20251001-v1:0}"

ok()   { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
try()  { # try "label" cmd...
  local label="$1"; shift
  local out; if out=$("$@" 2>&1); then ok "$label"; else bad "$label: $(echo "$out" | tail -1 | cut -c1-160)"; fi
}

echo "== Identity (profile: ${AWS_PROFILE:-<default>}, region: $REGION)"
ID=$(aws sts get-caller-identity --output text --query '[Account,Arn]' 2>&1) || { bad "sts: $ID"; exit 1; }
ACCOUNT=$(echo "$ID" | awk '{print $1}'); ARN=$(echo "$ID" | awk '{print $2}')
echo "  account $ACCOUNT"; echo "  arn     $ARN"
if [ -n "${EXPECT_ACCOUNT:-}" ] && [ "$ACCOUNT" != "$EXPECT_ACCOUNT" ]; then
  bad "expected account $EXPECT_ACCOUNT, got $ACCOUNT: wrong credentials, stopping"; exit 1
fi

echo "== Bedrock"
echo "  inference profiles matching anthropic:"
aws bedrock list-inference-profiles --query 'inferenceProfileSummaries[?contains(inferenceProfileId, `anthropic`)].inferenceProfileId' \
  --output text 2>&1 | tr '\t' '\n' | sed 's/^/    /'
TOOLS='{"tools":[{"toolSpec":{"name":"answer","description":"Return the answer.","inputSchema":{"json":{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"]}}}}],"toolChoice":{"tool":{"name":"answer"}}}'
TOOLS_AUTO='{"tools":[{"toolSpec":{"name":"answer","description":"Return the answer.","inputSchema":{"json":{"type":"object","properties":{"ok":{"type":"boolean"}},"required":["ok"]}}}}],"toolChoice":{"auto":{}}}'
MSG='[{"role":"user","content":[{"text":"Call the answer tool with ok=true."}]}]'
# Claude 5.5 models reject some request shapes (forced tool choice, non-default temperature). llm.py sends BOTH today
# (app/services/llm.py:112,119), so test that exact shape first, then each variant, to see what must change.
for M in "$HEAVY" "$LIGHT"; do
  echo "  -- $M"
  try "plain converse"                          aws bedrock-runtime converse --model-id "$M" --messages "$MSG" --inference-config '{"maxTokens":64}'
  try "llm.py shape (forced tool + temp 0)"     aws bedrock-runtime converse --model-id "$M" --messages "$MSG" --inference-config '{"maxTokens":256,"temperature":0}' --tool-config "$TOOLS"
  try "forced tool, no temperature"             aws bedrock-runtime converse --model-id "$M" --messages "$MSG" --inference-config '{"maxTokens":256}' --tool-config "$TOOLS"
  try "auto tool choice, no temperature"        aws bedrock-runtime converse --model-id "$M" --messages "$MSG" --inference-config '{"maxTokens":256}' --tool-config "$TOOLS_AUTO"
done
try "list guardrails" aws bedrock list-guardrails --max-results 1

echo "== EC2 / IAM / S3 / CloudFront / ECR (read-only probes)"
try "ec2 describe-instances"   aws ec2 describe-instances --max-results 5
try "ec2 describe-vpcs"        aws ec2 describe-vpcs
try "ec2 dry-run t3a.large"    bash -c "aws ec2 run-instances --dry-run --instance-type t3a.large \
  --image-id $(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64 --query Parameter.Value --output text) \
  2>&1 | grep -q DryRunOperation"
try "iam list-roles"           aws iam list-roles --max-items 1
try "iam list-instance-profiles" aws iam list-instance-profiles --max-items 1
try "s3 list-buckets"          aws s3api list-buckets --max-items 1
try "cloudfront list-distributions" aws cloudfront list-distributions --max-items 1
try "ecr describe-repositories" aws ecr describe-repositories --max-items 1
try "logs describe-log-groups" aws logs describe-log-groups --limit 1

echo "== Write permissions (IAM policy simulator; needs iam:SimulatePrincipalPolicy)"
SIM_ARN="$ARN"
case "$ARN" in *:assumed-role/*) SIM_ARN=$(echo "$ARN" | sed -E 's#:sts::([0-9]+):assumed-role/([^/]+)/.*#:iam::\1:role/\2#');; esac
ACTIONS="ec2:RunInstances iam:CreateRole iam:PassRole iam:CreateInstanceProfile s3:CreateBucket s3:PutBucketObjectLockConfiguration s3:PutObjectRetention cloudfront:CreateDistribution bedrock:CreateGuardrail bedrock:InvokeModel ecr:CreateRepository"
if out=$(aws iam simulate-principal-policy --policy-source-arn "$SIM_ARN" --action-names $ACTIONS \
    --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text 2>&1); then
  echo "$out" | sed -E 's/[[:space:]]+/ /g' | while read -r a d; do if [ "$d" = allowed ]; then ok "$a"; else bad "$a ($d)"; fi; done
  echo "  (simulator ignores SCPs; an org SCP can still deny. Real create calls are the final word.)"
else
  bad "simulator not permitted: $(echo "$out" | tail -1 | cut -c1-160)"
fi
