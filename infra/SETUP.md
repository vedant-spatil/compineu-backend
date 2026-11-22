# Setting up compineu on AWS: EC2, S3 and CloudWatch

This is the step-by-step guide. [README.md](README.md) is the short reference (options, cost, teardown). To build the
AWS resources by hand in the console, with the code coming from GitHub instead of S3, follow
[MANUAL-SETUP.md](MANUAL-SETUP.md).

Status: the scripts and the template in this folder were checked with `bash -n`, a dry run of `infra/box/setup.sh`,
`cfn-lint` and the unit tests. They have **not been run against AWS yet**, so expect to fix small things on the first
real deploy, and read [Troubleshooting](#troubleshooting) before you start.

## What you get

```
Browser ── CloudFront (HTTPS) ──┬── /*      S3 web bucket        (React build, private, Origin Access Control)
                                └── /api/*  EC2 box (no SSH)     nginx -> API (FastAPI + LangGraph) -> Postgres 16
                                                                  all three in Docker
EC2 instance role (no AWS keys on the box):
   S3 evidence bucket   put objects and set retention, never delete     (PB6, Object Lock COMPLIANCE)
   S3 artifacts bucket  read the backend tarball you ship
   SSM Parameter Store  read /compineu/prod/*  (JWT, PII key, Postgres, origin secret, admin and qa passwords, Groq key)
   CloudWatch Logs      write container logs; run Logs Insights queries for the Observability page
   CloudWatch metrics   host metrics from the CloudWatch agent, namespace compineu/EC2 only
Groq                    the LLM, called over HTTPS with the key from SSM (no model access to request in AWS)
```

## 1. Before you start

On your laptop (Git Bash, Linux, macOS or WSL):

- AWS CLI v2, `openssl`, `python` or `python3`, `tar`, `git`, Node 20 (for the frontend). For `aws ssm start-session`
  also install the Session Manager plugin.
- AWS credentials for the account you deploy to (a profile of your choice, written `<profile>` below), with admin or
  PowerUser plus IAM rights. `deploy.sh` refuses to run unless `EXPECT_ACCOUNT` matches the account of those credentials.
- A Groq API key.

Pick the instance size (default `t3a.medium`, 4 GB). Measured locally, the API takes about 1 GB, Postgres about 0.13 GB
and the OS about 0.4 GB, so the running system is about 1.5 GB. The data generator peaks at about 0.19 GB on top of
the API, and the data loader streams its input. The Docker build on the box was not measured. The compose memory caps
are 2 GB for the API, 1 GB for Postgres and 128 MB for nginx.

| Size | Use |
|---|---|
| `t3a.medium` (4 GB) | Default. About $0.85 a day running. Roughly 2.4 GB spare. |
| `t3a.large` (8 GB) | More headroom. `INSTANCE_TYPE=t3a.large bash infra/deploy.sh`. About $1.40 a day. |
| `t3a.small` (2 GB) | Only the finished system fits (about 0.4 GB spare). Use `--small` data and expect the build to be slow or fail. |

All commands below run from the `backend/` folder.

## 2. Create everything in AWS (one command)

```bash
export AWS_PROFILE=<profile> AWS_REGION=ap-south-1 EXPECT_ACCOUNT=<account-id>
read -rs GROQ_API_KEY; export GROQ_API_KEY      # type the key, nothing is echoed; needed on the first run only
bash infra/deploy.sh
unset GROQ_API_KEY
```

`deploy.sh` does two things.

1. It creates these secrets in SSM Parameter Store under `/compineu/prod/` (existing ones are kept): `JWT_SECRET_KEY`,
   `PII_ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, `ORIGIN_SECRET`, `ADMIN_PASSWORD`, `QA_PASSWORD`, `GROQ_API_KEY`,
   `GROQ_MODEL_HEAVY` and `GROQ_MODEL_LIGHT`.
2. It deploys the CloudFormation stack `compineu` from `compineu.yaml`. CloudFront takes 5 to 15 minutes the first time.

The stack creates:

| Resource | Name | Purpose |
|---|---|---|
| EC2 instance (Ubuntu 24.04, 30 GB encrypted gp3, IMDSv2 only) and an Elastic IP | `compineu-box` | Runs Docker. No SSH port; shell access is SSM Session Manager. |
| Security group | `compineu-box` | Port 80 from the CloudFront origin-facing prefix list only. |
| S3 evidence bucket (Object Lock COMPLIANCE, versioned, retained on stack delete) | `compineu-evidence-<account>-<region>` | PB6 evidence. 1 day retention by default. |
| S3 web bucket (private, served by CloudFront only) | `compineu-web-<account>-<region>` | The React build. |
| S3 artifacts bucket (objects expire after 7 days) | `compineu-artifacts-<account>-<region>` | The backend tarball. |
| CloudWatch log group (7 days) | `/compineu/prod` | Container logs. |
| IAM role and instance profile | `compineu-ec2-<region>` | Least-privilege access listed above. |
| CloudFront distribution | (stack output `AppUrl`) | One HTTPS origin for the page and `/api`. |
| VPC and subnet | only if the account has no default VPC | |

When it finishes, a table of stack outputs is printed (`AppUrl`, `InstanceId`, the three bucket names, `LogGroup`).
Re-read it any time:

```bash
aws cloudformation describe-stacks --stack-name compineu --query 'Stacks[0].Outputs[].[OutputKey,OutputValue]' --output table
```

## 3. Ship the backend and set up the box (one command)

```bash
bash infra/ship.sh                 # add --small for the small demo data set
```

`ship.sh` packs your working tree (git-tracked and new files, minus everything in `.gitignore`, so `.env` and `data/`
never leave your laptop), uploads the tarball to the artifacts bucket, and tells the box through SSM Run Command to pull
it and run `infra/box/setup.sh`. The first run builds the images and takes about 10 minutes, mostly the spaCy model.
Follow the progress with the `get-command-invocation` line it prints.

### What `setup.sh` does on the box

1. Writes `.env` from SSM (mode 600): Groq key and models, secrets, `AWS_REGION`, `EVIDENCE_BUCKET`, the log group.
2. Builds the Docker images and starts Postgres, waiting until it accepts connections.
3. Starts the API and nginx. The API container runs `alembic upgrade head` on start, so migrations apply automatically.
4. Creates two users with passwords read from SSM: `admin@compineu.dev` (role `admin`) and `qa@compineu.dev` (role `qa`,
   a reviewer that an admin assigns cases to). Running it again resets their passwords to the SSM values.
5. Seeds the synthetic demo world, only if the database has no policyholders yet: 50,000 policyholders, 212 agents and
   about 188,700 history events (seed 42). It never touches cases, alerts or the audit trail.
6. Installs the CloudWatch agent for host metrics (memory, swap, disk, CPU), unless you pass `--no-agent`.
7. Prints the health check, row counts, and where to find the passwords.

Options (also accepted by `ship.sh`): `--small` (small fixture instead of the full world), `--reseed` (wipe the demo
rows and load again), `--no-seed`, `--no-agent`. `DRY_RUN=1` prints the steps without running them.

### Running it by hand on the box

Use this if you want to pull the backend from S3 yourself. From your laptop, find the tarball (the instance role can read
objects but not list the bucket):

```bash
ART=compineu-artifacts-<account-id>-ap-south-1       # the ArtifactsBucket output
aws s3 ls s3://$ART/ --profile <profile>             # backend-<sha>.tgz
aws cloudformation describe-stacks --stack-name compineu --query "Stacks[0].Outputs[?OutputKey=='InstanceId'].OutputValue" --output text
aws ssm start-session --target <instance-id> --profile <profile>
```

On the box:

```bash
sudo -i
cd /opt/compineu && rm -rf app && mkdir app
aws s3 cp s3://compineu-artifacts-<account-id>-ap-south-1/backend-<sha>.tgz /tmp/backend.tgz
tar -xzf /tmp/backend.tgz -C app && cd app
# first time only: the non-secret names (ship.sh does this for you, and setup.sh saves them in /opt/compineu/box.env)
export AWS_REGION=ap-south-1 SSM_PREFIX=/compineu/prod LOG_GROUP=/compineu/prod
export EVIDENCE_BUCKET=compineu-evidence-157205473853-ap-south-1
export APP_URL=https://<the AppUrl output>
bash infra/box/setup.sh            # or: bash infra/box/setup.sh --small
```

## 4. Publish the frontend

```bash
bash ../frontend/deploy/ship-web.sh
```

It builds the React app, syncs it to the web bucket and invalidates CloudFront. The page and the API share one origin,
so no CORS settings are needed. Open the `AppUrl` and sign in as `admin@compineu.dev`. Read the password (it is never
printed by any script):

```bash
aws ssm get-parameter --name /compineu/prod/ADMIN_PASSWORD --with-decryption --query Parameter.Value --output text
```

## 5. How S3 and CloudWatch are connected

**S3 evidence (PB6).** When an analyst approves the PB6 playbook, `app/services/evidence.py` writes the evidence bundle
to `EVIDENCE_BUCKET` with `ObjectLockMode=COMPLIANCE` and a retention date. The instance role may put objects and set
retention but is explicitly denied delete and any change to the lock configuration. Nobody, including root, can delete
the object before the retention date. The receipt (bucket, key, version, SHA-256, retain-until) is written to the
append-only audit trail. Settings: `EVIDENCE_BUCKET`, `AWS_REGION`, `EVIDENCE_RETENTION_DAYS`.

**CloudWatch Logs.** Each container ships its output to the log group `/compineu/prod` through Docker's `awslogs`
driver (`docker-compose.prod.yml`), one stream per container (`postgres`, `api`, `nginx`). `docker logs` on the box is
empty by design. The admin Observability page runs Logs Insights queries against the same group (settings
`OBSERVABILITY_LOG_GROUP`, `AWS_REGION`).

**CloudWatch metrics and alarms.** The CloudWatch agent (installed by `setup.sh`) publishes memory, swap, disk and CPU to
the namespace `compineu/EC2`. Alarms and log metric filters are created from your laptop, because the instance role
cannot create them:

```bash
AWS_REGION=ap-south-1 AWS_LOG_GROUP=/compineu/prod bash scripts/aws/02-logs.sh           # metric filters (nginx 5xx, API errors); also sets 14-day retention
INSTANCE_ID=<instance-id> AWS_REGION=ap-south-1 bash scripts/aws/04-alarms.sh you@example.com   # SNS topic plus 7 alarms; confirm the email
```

## 6. Verify it works

| Check | How | Expect |
|---|---|---|
| API health | `bash infra/demo/smoke.sh S1` (replays a scenario, prints the outcome, resets) | Case awaiting review, risk about 0.887 |
| Login | open `AppUrl` | Dashboard shows CERT-In clocks and records at risk |
| PB6 to S3 | `bash infra/demo/approve_e2e.sh S1 PB1,PB6,PB7 AG-1147`, then `bash infra/demo/show_evidence.sh` | Object with `ObjectLockMode COMPLIANCE`; the agent gets 403 |
| Logs | CloudWatch console, Log groups, `/compineu/prod`, or `aws logs filter-log-events --log-group-name /compineu/prod` | Streams `api`, `nginx`, `postgres` |
| Observability page | sign in as admin, open Observability | Charts, not a 502 or "not configured" |
| Metrics | CloudWatch console, Metrics, `compineu/EC2` | `mem_used_percent` and others, a few minutes after setup |

Evidence is written with the default 1-day retention and cannot be removed before it ends. Approve PB6 only when you
mean it.

## 7. Launching the box from the console instead of the stack

The console "Launch an instance" form creates only the EC2 box. `deploy.sh` also creates CloudFront, the three S3
buckets, the log group, the IAM role and the SSM secrets, and the app needs all of them, so the stack is the easier
route. If you still launch by hand, set the form like this and create the rest yourself:

| Form field | Value |
|---|---|
| Account | The account you mean to deploy to (check the account id at the top right of the console). |
| Name | `compineu-box` |
| AMI | Ubuntu Server 24.04 LTS, 64-bit (x86) |
| Instance type | `t3a.medium` |
| Storage | 20 GiB or more gp3, and tick **Encrypted** under Advanced |
| Security group | Port 80 only from the CloudFront origin-facing prefix list (`com.amazonaws.global.cloudfront.origin-facing`). Drop HTTPS: nothing on the box listens on 443. SSH from your own IP only if you want it; Session Manager needs no SSH. |
| IAM instance profile | **Required.** A role with the managed policy `AmazonSSMManagedInstanceCore` plus an inline policy made from `infra/box/instance-policy.json` (replace `EVIDENCE_BUCKET`, `ARTIFACTS_BUCKET`, `REGION` and `ACCOUNT_ID`). It reads `/compineu/prod/*` in SSM, puts to the evidence bucket without delete, reads the artifacts bucket, and writes CloudWatch logs and metrics. Trust policy: EC2. Without it `setup.sh` cannot read its secrets. |
| Credit specification | Unlimited (the default) |
| Metadata version / hop limit | V2 only, hop limit **2** (containers need the second hop to reach the role) |
| User data | Choose the file `infra/box/user-data.sh` |
| Public IP | Allocate an Elastic IP afterwards; an auto-assigned address changes when the box stops |

Before running `setup.sh` on that box you also need: the SSM secrets (`bash infra/deploy.sh` creates them, or create the
same names by hand), the evidence bucket with Object Lock, the log group `/compineu/prod`, and a CloudFront distribution
in front of port 80. The box's nginx refuses any request that lacks CloudFront's secret `X-Origin-Verify` header, so
opening the instance's IP in a browser gives a refusal, not the app.

## 8. If you do not use the stack (by hand)

The two resources the app needs most can be created with the CLI. The IAM policy for your own role needs `s3:PutObject`,
`s3:PutObjectRetention`, `s3:GetObject` on the evidence bucket, and `logs:CreateLogStream`, `logs:PutLogEvents`,
`logs:StartQuery`, `logs:GetQueryResults` for CloudWatch (the exact statements are in `compineu.yaml`).

```bash
# Evidence bucket with Object Lock (simplest to enable at creation; an existing bucket needs versioning on first)
aws s3api create-bucket --bucket <name> --region ap-south-1 --create-bucket-configuration LocationConstraint=ap-south-1 --object-lock-enabled-for-bucket
aws s3api put-object-lock-configuration --bucket <name> --object-lock-configuration \
  '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":1}}}'
# Log group
aws logs create-log-group --log-group-name /compineu/prod --region ap-south-1
aws logs put-retention-policy --log-group-name /compineu/prod --retention-in-days 7 --region ap-south-1
```

Then set `EVIDENCE_BUCKET`, `AWS_REGION`, `OBSERVABILITY_LOG_GROUP` and `AWS_LOG_GROUP` in the API's `.env`.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `deploy.sh`: `set EXPECT_ACCOUNT` or `wrong account` | Export `EXPECT_ACCOUNT=<account-id>` and `AWS_PROFILE=<profile>`. |
| `deploy.sh`: `secret GROQ_API_KEY is missing` | First deploy needs `GROQ_API_KEY` in your shell (see step 2). |
| `ship.sh`: `box still bootstrapping` | The instance is still running its first-boot script. Wait a few minutes and run again. |
| Build killed or very slow on the box | Out of memory (likely on a `t3a.small`). Use `t3a.medium` or larger; the 2 GB swap file helps but is slow. |
| `setup.sh` times out waiting for the API | A slow first start (spaCy model). The script prints the last log lines; also read the CloudWatch streams. |
| Observability page 502 or "not configured" | `OBSERVABILITY_LOG_GROUP` empty, wrong `AWS_REGION`, or the role lacks `logs:StartQuery`. Check `/opt/compineu/app/.env` names (not values). |
| PB6 fails with "S3 refused the evidence write" | Wrong bucket or region, or the bucket was not created with Object Lock. Check `EVIDENCE_BUCKET` and `AWS_REGION`. |
| Cases fail with a Groq error | Free-tier rate limit (HTTP 429) or a bad key. Use a paid key for a live demo; the app retries three times. |
| New admin password does not work | Run `bash infra/bootstrap.sh` (resets the demo users to the SSM values) or `setup.sh` on the box. |

To remove everything, see `bash infra/teardown.sh` in [README.md](README.md). The evidence bucket stays by design.
