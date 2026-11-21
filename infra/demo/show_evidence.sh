#!/usr/bin/env bash
# Live-demo helper: show the newest evidence object in the S3 Object Lock bucket and its lock settings.
#   AWS_PROFILE=hackathon bash infra/demo/show_evidence.sh [CASE_ID]
# With a case id it shows that case's newest object (incidents/<id>/...); without one, the newest overall.
# Read-only. The object cannot be deleted or overwritten until the retention date shown.
export AWS_REGION=ap-south-1 MSYS_NO_PATHCONV=1
BUCKET=policyguard-evidence-389070778843
PREFIX="incidents/${1:+$1/}"
KEY=$(aws s3api list-objects-v2 --bucket "$BUCKET" --prefix "$PREFIX" \
  --query 'sort_by(Contents,&LastModified)[-1].Key' --output text 2>/dev/null)
if [ -z "$KEY" ] || [ "$KEY" = "None" ]; then echo "  no evidence object under s3://$BUCKET/$PREFIX yet (approve with PB6 first)"; exit 1; fi
echo
echo "  s3://$BUCKET/$KEY"
aws s3api head-object --bucket "$BUCKET" --key "$KEY" \
  --query '{size_bytes:ContentLength, written:LastModified, lock_mode:ObjectLockMode, retained_until:ObjectLockRetainUntilDate, sha256_in_name:Metadata."sha256"}' --output table
echo
