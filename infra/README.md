# Deploying compineu to AWS

One EC2 box (Docker: Postgres, API, nginx) behind CloudFront, private S3 buckets and an S3 Object Lock evidence
bucket. The LLM is Groq, called over HTTPS with an API key kept in SSM Parameter Store, so there is no model access to
request in AWS. There is no ECS, Fargate or Bedrock in this stack.

`compineu.yaml` is self-contained and has no hard-coded account, region or resource ids. Everything that differs per
account (VPC, subnet, CloudFront prefix list, secrets) is resolved by `deploy.sh`. Every other script reads names from
the stack outputs.

Deploys go to the hackathon account only (`AWS_PROFILE=hackathon`, account `389070778843`). `deploy.sh` refuses to run
unless `EXPECT_ACCOUNT` matches the account the credentials belong to.

## Before you start (once per account)

1. AWS CLI v2 configured for the target account, with admin or PowerUser plus IAM rights.
2. A Groq API key. It goes into SSM on the first deploy and is never printed or written to a file.
3. Git Bash or Linux/macOS bash, `openssl`, `python` or `python3`, and Node 20 for the frontend.

## Deploy (about 25 minutes the first time)

```bash
export AWS_PROFILE=hackathon AWS_REGION=ap-south-1 EXPECT_ACCOUNT=389070778843
read -rs GROQ_API_KEY; export GROQ_API_KEY    # first deploy only (typed, not echoed); later runs keep the SSM value
bash infra/deploy.sh                          # secrets in SSM, then the stack (CloudFront takes 5-15 min)
unset GROQ_API_KEY
bash infra/ship.sh                            # backend: tarball -> S3 -> box runs infra/box/setup.sh (first build ~10 min):
                                              #   .env from SSM, images, Postgres, migrations, users, demo data, CloudWatch agent
bash ../frontend/deploy/ship-web.sh           # React build -> web bucket -> CloudFront invalidation
```

Run these from `backend/`. `ship.sh --small` loads the small demo data set; `bash infra/bootstrap.sh` wipes the demo
rows and loads them again later. The full walk-through (EC2, S3, CloudWatch, running `setup.sh` by hand on the box,
verification and troubleshooting) is in [SETUP.md](SETUP.md). The admin and qa users are `admin@compineu.dev` and
`qa@compineu.dev`. To read the admin password:

```bash
aws ssm get-parameter --name /compineu/prod/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text
```

| Option (env var for `deploy.sh`) | Default | Meaning |
|---|---|---|
| `PROJECT` | `compineu` | Name prefix and SSM path `/<PROJECT>/prod`. Use a different value for a second copy in the same account. |
| `INSTANCE_TYPE` | `t3a.medium` | x86_64, 4 GB. Measured about 1.5 GB in use; `t3a.large` (8 GB) for more headroom. |
| `CREATE_VPC` | unset | `1` builds a dedicated VPC. This happens automatically when the account has no default VPC. |
| `GROQ_MODEL_HEAVY` / `GROQ_MODEL_LIGHT` | `openai/gpt-oss-120b` / `openai/gpt-oss-20b` | Groq model ids, stored in SSM and written to the box `.env` by `ship.sh`. |
| `EVIDENCE_RETENTION_DAYS` | `1` | Object Lock COMPLIANCE days. Nobody, root included, can delete evidence earlier. Use 365 for production. |

Bucket names are `<project>-{web,evidence,artifacts}-<account>-<region>`. IAM and CloudFront names carry the region,
so one account can hold the stack in two regions.

## Secrets

Nothing secret is in this folder. `deploy.sh` generates the JWT, PII encryption, Postgres, origin and admin secrets
with `openssl` and stores them under `/compineu/prod/` as SSM SecureStrings. The Groq key comes from your shell and goes
to the same place. The box reads them with its instance role (no AWS keys on the box) and writes `.env` with mode 600.
`.env` files are git-ignored and `ship.sh` never uploads them.

## Observability

- Container logs go to the CloudWatch log group `/compineu/prod` (the `awslogs` driver in `docker-compose.prod.yml`).
- Host metrics: `setup.sh` installs the CloudWatch agent (`scripts/aws/03-cw-agent.sh`, namespace `compineu/EC2`).
- Metric filters and alarms, from your laptop: `scripts/aws/02-logs.sh` and `scripts/aws/04-alarms.sh <email>`.

## Teardown

```bash
bash infra/teardown.sh                # asks you to type the stack name
```

With `DELETE_SECRETS=1` it also removes the SSM secrets. It empties the web and artifacts buckets and deletes the stack.

The evidence bucket is retained on purpose, because Object Lock COMPLIANCE objects can't be deleted before their
retention ends. Empty and delete it after that date.

## Estimated cost per day, excluding Groq

On-demand Linux, default settings (`t3a.medium`, 30 GB gp3, 1 Elastic IP), demo-level traffic. The EC2 row is half the
earlier `t3a.large` figures ($0.0493/h Mumbai and $0.0752/h us-east-1 for large), not a fresh price lookup.

| Item | ap-south-1 (Mumbai) | us-east-1 | Notes |
|---|---|---|---|
| EC2 `t3a.medium` (24 h) | **$0.59** ($0.0247/h) | $0.90 ($0.0376/h) | Most of the bill. |
| EBS gp3 30 GB | $0.09 | $0.08 | About $0.09/GB-month. |
| Public IPv4 (Elastic IP) | $0.12 | $0.12 | $0.005/h, charged even while the box is stopped. |
| CloudWatch Logs (7-day retention) | about $0.01-0.05 | about $0.01-0.05 | A demo writes tens of MB a day. |
| CloudFront | $0 | $0 | The always-free tier covers 1 TB and 10 M requests a month. |
| S3 (3 buckets, a few MB) | under $0.01 | under $0.01 | |
| SSM Parameter Store, Run Command, Session Manager, KMS `aws/ssm` key | $0 | $0 | Standard parameters and the AWS managed key are free. |
| **Total, running** | **about $0.85/day (about $26/month)** | **about $1.15/day (about $35/month)** | |
| **Total, box stopped** | about $0.21/day | about $0.20/day | Only EBS and the Elastic IP. |

Caveats:

- **CPU credits.** T3a runs in "unlimited" credit mode by default. Normal use stays under the baseline (20% of each of
  the 2 vCPUs on `t3a.medium`) and costs nothing extra. A box pegged at 100% all day would add up to about $1.92/day
  ($0.05 per vCPU-hour above baseline).
- **Ways to cut the bill.** Stop the box when it isn't in use; a 1-year Compute Savings Plan cuts EC2 by about 30-40%.
  `t3a.large` (8 GB) doubles the EC2 line; `t3a.small` (2 GB) halves it again but leaves about 0.4 GB of headroom and
  the Docker build may fail.
- **Not included.** Groq usage (the free tier is rate limited, so a paid key is safer for a live demo), data transfer
  above the CloudFront free tier, and tax. Prices are from public price lists as of November 2026. Check them in the
  AWS Pricing Calculator before you rely on them.
