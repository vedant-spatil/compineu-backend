# Sourced by the demo helpers and by bootstrap.sh / teardown.sh: resolves the box, URL, evidence bucket and SSM path
# from the stack outputs, so they work in any account and region.   STACK (default $PROJECT or compineu), AWS_REGION.
export MSYS_NO_PATHCONV=1 AWS_REGION="${AWS_REGION:-ap-south-1}"
command -v python >/dev/null || python() { python3 "$@"; }   # plain Ubuntu has python3 only
STACK="${STACK:-${PROJECT:-compineu}}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@compineu.dev}"
_out() { aws cloudformation describe-stacks --stack-name "$STACK" --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text | tr -d '\r'; }
I=$(_out InstanceId); U=$(_out AppUrl); BUCKET=$(_out EvidenceBucket); PREFIX=$(_out SsmPrefix)
[ -n "$I" ] && [ "$I" != "None" ] || { echo "stack $STACK not found in $AWS_REGION" >&2; exit 1; }
