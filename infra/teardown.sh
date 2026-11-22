#!/usr/bin/env bash
# Deletes the compineu stack: empties the web and artifacts buckets, then deletes the stack.
#   AWS_PROFILE=hackathon AWS_REGION=<region> bash infra/teardown.sh            (asks you to type the stack name)
#   DELETE_SECRETS=1 ... also deletes the SSM secrets under /<project>/prod.
# Kept on purpose: the evidence bucket (Object Lock COMPLIANCE). Delete it yourself once its retention has ended:
#   aws s3api delete-objects / delete-bucket, or the S3 console "Empty" then "Delete".
set -euo pipefail
. "$(dirname "$0")/demo/_stack.sh"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
echo "about to DELETE stack $STACK in account $ACCOUNT, region $AWS_REGION (box, database, CloudFront, buckets)"
read -r -p "type the stack name to confirm: " ANSWER
[ "$ANSWER" = "$STACK" ] || { echo "not confirmed, nothing deleted"; exit 1; }
for B in $(_out WebBucket) $(_out ArtifactsBucket); do
  echo "emptying s3://$B"; aws s3 rm "s3://$B" --recursive --only-show-errors
done
aws cloudformation delete-stack --stack-name "$STACK"
echo "waiting for delete (CloudFront takes a few minutes)"
aws cloudformation wait stack-delete-complete --stack-name "$STACK"
if [ -n "${DELETE_SECRETS:-}" ]; then
  for N in $(aws ssm get-parameters-by-path --path "$PREFIX" --query 'Parameters[].Name' --output text); do
    aws ssm delete-parameter --name "$N"; echo "deleted $N"
  done
fi
echo "deleted. still there: s3://$BUCKET (Object Lock) and, unless DELETE_SECRETS=1, the SSM secrets under $PREFIX"
