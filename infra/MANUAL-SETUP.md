# Setup in the AWS console (clicks, not commands)

Step-by-step for building compineu by hand in the AWS console, with the backend code cloned from GitHub. The order is:
CloudWatch, S3 policies, secrets (a `.env` file on the box), IAM role, EC2, CloudFront, backend on the box, frontend
upload, checks.
[SETUP.md](SETUP.md) is the automated route (CloudFormation); this guide does not need the command line, except in three
places that cannot be done with clicks: the `git clone`, the `.env` block and `setup.sh` on the box (step 6), and
building the frontend on your PC (step 8).

Status: written from the project's design. It has **not been run against AWS**, so the first run is also a test. Console
labels change over time; if one here does not match, pick the closest option.

Values used below. Change them if yours differ.

| Item | Value |
|---|---|
| AWS account id | `157205473853` |
| Region | Asia Pacific (Mumbai) `ap-south-1` |
| Evidence bucket (Object Lock) | `compineu-evidence-157205473853-ap-south-1` (already created) |
| Web bucket | `compineu-web-157205473853-ap-south-1` |
| Artifacts bucket | `compineu-artifacts-157205473853-ap-south-1` (not used on this route; leave it empty) |
| Log group | `/compineu/prod` |
| Backend repo | `https://github.com/<github-owner>/compineu-backend.git` |
| Frontend repo | `https://github.com/<github-owner>/compineu-frontend.git` |

Every step starts in the console, signed in to account `157205473853`, with the region selector (top right) on
**Asia Pacific (Mumbai)**. Click your account name at the top right to see the account id and check it.

Before you start, commit and push the frontend repo. It has uncommitted sign-up page changes that the build needs.

## 1. CloudWatch: the log group

The box's role can write to the log group but cannot create it, so create it first.

1. Search for **CloudWatch** in the top search bar and open it.
2. Left menu: **Logs**, then **Log management** (older consoles: **Log groups**). Click **Create log group**.
3. Log group name: `/compineu/prod` (with the leading slash).
4. Retention setting: **1 week (7 days)**. Log class: **Standard**. Leave encryption empty.
5. Click **Create**.

Container logs will appear here by themselves once the box runs, one stream per container (`api`, `nginx`, `postgres`).

## 2. S3: bucket policies

For each bucket: S3, click the bucket name, **Permissions** tab, scroll to **Bucket policy**, **Edit**, paste the JSON,
**Save changes**. Keep **Block all public access** on; these policies do not make anything public.

**Evidence bucket** (you already did this one). It refuses non-HTTPS access:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::compineu-evidence-157205473853-ap-south-1",
      "arn:aws:s3:::compineu-evidence-157205473853-ap-south-1/*"
    ],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }]
}
```

Also check this bucket's **Properties** tab: Bucket Versioning **Enabled**, Object Lock **Enabled**, Default retention
**Compliance, 1 day**. If the default retention is missing, click Edit under Object Lock and set it. Evidence objects cannot
be deleted before their retention date, by anyone.

**Artifacts bucket** (optional, only if you ever use it). Same policy with this bucket's name:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::compineu-artifacts-157205473853-ap-south-1",
      "arn:aws:s3:::compineu-artifacts-157205473853-ap-south-1/*"
    ],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }]
}
```

**Web bucket.** For now paste only the HTTPS rule. The statement that lets CloudFront read the files is added in step 7,
because it needs the CloudFront distribution id.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::compineu-web-157205473853-ap-south-1",
      "arn:aws:s3:::compineu-web-157205473853-ap-south-1/*"
    ],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }]
}
```

## 3. Secrets: a `.env` file on the box

There is nothing to click in AWS for secrets. The box reads its settings and secrets from one file,
`/opt/compineu/app/.env`, which you create on the box in step 6 with a ready-made block. That block generates the random
values and does not show them. Have your **Groq API key** ready.

What the file holds, and what `setup.sh` checks (by key name and format only; it never prints a value):

| Key | Value |
|---|---|
| `GROQ_API_KEY` | your Groq key |
| `JWT_SECRET_KEY` | 32 or more random letters and digits |
| `PII_ENCRYPTION_KEY` | exactly 43 random letters, digits, `-` or `_`, then `=` (44 characters in all) |
| `POSTGRES_PASSWORD` | random letters and digits only (it goes into a connection address) |
| `ORIGIN_SECRET` | 32 or more random letters and digits; the same value goes into CloudFront in step 7 |
| `EVIDENCE_BUCKET`, `AWS_REGION`, `AWS_LOG_GROUP`, `OBSERVABILITY_LOG_GROUP` | the S3 and CloudWatch names. These are names, not secrets |
| `ADMIN_PASSWORD`, `QA_PASSWORD` | 12 or more characters; the logins for `admin@compineu.dev` and `qa@compineu.dev` |

Rules: no spaces, quotes or `$` signs in a secret. Never commit this file (both repos already ignore `.env`). The file
is created with mode 600 and the box's disk is encrypted. Keep the admin password in a password manager.

Step 6 (the box) creates the file, and step 7 (CloudFront) needs the `ORIGIN_SECRET` value from it, so the box comes
first.

## 4. IAM role for the box

1. Search for **IAM**. Left menu: **Roles**, **Create role**.
2. Trusted entity type **AWS service**, use case **EC2**, **Next**.
3. In the search box type `AmazonSSMManagedInstanceCore`, tick it, **Next**. (This is what lets you open a terminal with
   Session Manager.)
4. Role name `compineu-ec2-ap-south-1`, **Create role**.
5. Open the new role, **Permissions** tab, **Add permissions**, **Create inline policy**, switch to the **JSON** tab,
   replace everything with the policy below, **Next**, name it `compineu-app`, **Create policy**.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EvidenceWriteNoDelete",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:PutObjectRetention", "s3:GetObject", "s3:GetObjectRetention", "s3:GetObjectVersion"],
      "Resource": "arn:aws:s3:::compineu-evidence-157205473853-ap-south-1/*"
    },
    {
      "Sid": "EvidenceList",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::compineu-evidence-157205473853-ap-south-1"
    },
    {
      "Sid": "NeverDeleteEvidence",
      "Effect": "Deny",
      "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:PutBucketObjectLockConfiguration"],
      "Resource": [
        "arn:aws:s3:::compineu-evidence-157205473853-ap-south-1",
        "arn:aws:s3:::compineu-evidence-157205473853-ap-south-1/*"
      ]
    },
    {
      "Sid": "LogsWrite",
      "Effect": "Allow",
      "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
      "Resource": "arn:aws:logs:ap-south-1:157205473853:log-group:/compineu/prod:*"
    },
    {
      "Sid": "LogsQueryForObservabilityPage",
      "Effect": "Allow",
      "Action": ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults", "logs:DescribeLogGroups"],
      "Resource": "*"
    },
    {
      "Sid": "HostMetricsFromCloudWatchAgent",
      "Effect": "Allow",
      "Action": "cloudwatch:PutMetricData",
      "Resource": "*",
      "Condition": { "StringEquals": { "cloudwatch:namespace": ["compineu/EC2"] } }
    }
  ]
}
```

What this allows: put evidence into the evidence bucket and set its retention, but never delete it or change the lock;
write the CloudWatch log group, run log queries for the Observability page, and send host metrics. There is no secrets
permission because the secrets live in the `.env` file, and no Bedrock permission because the LLM is Groq. It needs no
access to the artifacts or web buckets on this route (the web bucket is read by CloudFront, not by the box).

## 5. EC2: the box

**5a. Security group.** Search **EC2**. Left menu: **Security Groups**, **Create security group**.

- Name `compineu-box`, description `compineu box: HTTP from CloudFront only`, VPC: the default one.
- Inbound rules, **Add rule**: Type **HTTP**, port 80, Source **Custom**, click the search box and pick the AWS managed
  prefix list **`com.amazonaws.global.cloudfront.origin-facing`**. If it does not appear, open **VPC**, **Managed prefix
  lists**, copy the id (`pl-...`) of that list, and paste it into the Source box.
- No HTTPS rule: the box serves plain HTTP only to CloudFront. Shell access is Session Manager. If you also want SSH,
  add a second **inbound** rule: type SSH, port 22, source **My IP** (never `0.0.0.0/0`). It needs the instance's key
  pair, and the rule must be updated when your home IP changes.
- Outbound rules: leave the default (all traffic). The box needs it for Docker, Groq and the AWS services.
- **Create security group.**

**5b. Launch.** EC2, **Launch instances**:

| Field | Value |
|---|---|
| Name | `compineu-box` |
| Application and OS image | **Ubuntu**, Ubuntu Server 24.04 LTS, 64-bit (x86) |
| Instance type | `t3a.medium` (2 vCPU, 4 GiB) |
| Key pair | **Proceed without a key pair** (you use Session Manager). A key pair is only a spare way in. |
| Network settings, Edit | VPC default, any subnet, **Auto-assign public IP: Enable**, **Select existing security group**: `compineu-box` |
| Configure storage | 1 volume, **20 GiB**, gp3. Expand **Advanced** and set **Encrypted: Yes** |
| Advanced details, IAM instance profile | `compineu-ec2-ap-south-1` |
| Advanced details, Credit specification | Unlimited |
| Advanced details, Metadata version | **V2 only (token required)** |
| Advanced details, Metadata response hop limit | **2** |
| Advanced details, User data | paste the script below (or **Choose file**: `infra/box/user-data.sh`) |

User data (leave "User data has already been base64 encoded" unticked):

```bash
#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
apt-get update -y
apt-get install -y ca-certificates curl git jq unzip
command -v docker || curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
systemctl enable --now docker
snap install aws-cli --classic || true
mkdir -p /opt/compineu && chown ubuntu:ubuntu /opt/compineu
echo ready > /opt/compineu/.bootstrapped
```

Click **Launch instance**.

**5c. Elastic IP.** EC2 left menu: **Elastic IPs**, **Allocate Elastic IP address**, **Allocate**. Select it,
**Actions**, **Associate Elastic IP address**, pick `compineu-box`, **Associate**. Without this the address changes
whenever the box stops.

**5d. Note the public DNS name.** EC2, **Instances**, click `compineu-box`. Copy **Public IPv4 DNS** (it looks like
`ec2-13-x-x-x.ap-south-1.compute.amazonaws.com`). CloudFront needs this name, not the bare IP.

**5e. Wait, then connect.** The first-boot script needs 3 to 5 minutes. Then select the instance, **Connect**, tab
**Session Manager**, **Connect**. A terminal opens in your browser. If the Connect button is grey, the role is not
attached or the box has not registered yet: check **Actions, Security, Modify IAM role**, wait a few minutes and refresh.

## 6. Put the backend on the box

This is the first of the terminal steps. In the Session Manager terminal from step 5e:

```bash
sudo -i
cd /opt/compineu
git clone https://github.com/<github-owner>/compineu-backend.git app
```

If the repo is **private**, give the box a read-only deploy key instead. In the terminal run
`ssh-keygen -t ed25519 -f /root/.ssh/compineu_deploy -N ""` and then `cat /root/.ssh/compineu_deploy.pub`, copy the
public key it prints, and in GitHub open the backend repo, **Settings, Deploy keys, Add deploy key**: paste it and leave
"Allow write access" **off**. Back in the terminal clone with:

```bash
GIT_SSH_COMMAND="ssh -i /root/.ssh/compineu_deploy -o StrictHostKeyChecking=accept-new" git clone git@github.com:<github-owner>/compineu-backend.git app
git -C app config core.sshCommand "ssh -i /root/.ssh/compineu_deploy"
```

**Create the `.env` file.** This block generates every random secret on the box and shows none of them. Type or paste
your Groq key when asked (nothing appears as you type), and replace the web address with your CloudFront domain name
(or leave it and edit it after step 7 with `nano .env`, then run `bash infra/box/setup.sh --local-env --no-seed`; the page
and the API share one address, so it is not critical):

```bash
cd /opt/compineu/app
umask 077
read -rs GROQ_API_KEY
cat > .env <<EOF
APP_ENV=prod
CORS_ORIGINS=https://dxxxxxxxx.cloudfront.net
LLM_PROVIDER=groq
GROQ_API_KEY=$GROQ_API_KEY
LLM_MODEL_HEAVY=openai/gpt-oss-120b
LLM_MODEL_LIGHT=openai/gpt-oss-20b
JWT_SECRET_KEY=$(openssl rand -hex 32)
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=60
PII_ENCRYPTION_KEY=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\n')
POSTGRES_PASSWORD=$(openssl rand -hex 16)
ORIGIN_SECRET=$(openssl rand -hex 20)
TRIAGE_MODEL=rules
TRIAGE_THRESHOLD=0.40
EVIDENCE_BUCKET=compineu-evidence-157205473853-ap-south-1
AWS_REGION=ap-south-1
AWS_LOG_GROUP=/compineu/prod
OBSERVABILITY_LOG_GROUP=/compineu/prod
OBSERVABILITY_REGION=ap-south-1
CASE_RUNNER=local
ADMIN_PASSWORD=$(openssl rand -hex 8)
QA_PASSWORD=$(openssl rand -hex 8)
EOF
unset GROQ_API_KEY
```

To review or change it, open it with `nano .env` (save with Ctrl+O then Enter, exit with Ctrl+X). If you would rather type
the values yourself, create the same lines in nano and follow the rules in step 3. Check the file before the long build:

```bash
bash infra/box/setup.sh --check-env
```

It lists any missing key or wrong format by name (never a value) and starts nothing. Now read the `ORIGIN_SECRET` for
CloudFront (step 7) with `grep '^ORIGIN_SECRET=' .env`, and the logins you will use with
`grep -E '^(ADMIN|QA)_PASSWORD=' .env`. Then run the setup. It builds the Docker images, starts Postgres, the API and
nginx (the API applies the database migrations on start), creates the `admin@compineu.dev` and `qa@compineu.dev` users,
loads the demo data, installs the CloudWatch agent and checks health:

```bash
bash infra/box/setup.sh --local-env
```

The first build takes about 10 minutes (the spaCy model layer). It ends with row counts and a summary. Add `--small` for
the small demo data set. After you have saved the two passwords in a password manager, delete the `ADMIN_PASSWORD` and
`QA_PASSWORD` lines from `.env` (`nano .env`); the users already exist. To update after you push new backend code:

```bash
cd /opt/compineu/app && git pull && bash infra/box/setup.sh --local-env --no-seed
```

## 7. CloudFront: one address for the page and the API

New AWS accounts are sometimes asked to verify the account before creating a distribution. If so, follow the prompt.

**7a. The page-route function.** Search **CloudFront**. Left menu: **Functions**, **Create function**. Name
`compineu-spa-rewrite`, runtime `cloudfront-js-2.0`, **Create function**. Replace the code with the following, **Save
changes**, then open the **Publish** tab and click **Publish function**:

```js
function handler(event) {
  var req = event.request;
  var last = req.uri.split('/').pop();
  if (last.indexOf('.') === -1) { req.uri = '/index.html'; }
  return req;
}
```

**7b. Create the distribution.** Left menu: **Distributions**, **Create distribution**.

1. Origin type **Amazon S3**. Origin domain: pick the web bucket `compineu-web-157205473853-ap-south-1`. Origin access:
   **Origin access control settings (recommended)**, then **Create new OAC** with the defaults, and **Create**. Origin
   name `web`.
2. Default cache behavior: Viewer protocol policy **Redirect HTTP to HTTPS**. Allowed HTTP methods **GET, HEAD**. Cache
   policy **CachingOptimized**. Response headers policy **SecurityHeadersPolicy**. Compress objects automatically **Yes**.
   Function associations, **Viewer request**: Function type **CloudFront Functions**, function `compineu-spa-rewrite`.
3. Settings: Price class **Use North America, Europe, Asia, Middle East and Africa**. Default root object `index.html`.
   Do **not** enable WAF.
4. **Create distribution.** CloudFront then shows a banner with an S3 bucket policy and a **Copy policy** button; leave
   it for step 7e.

**7c. Add the API origin.** Open the distribution, tab **Origins**, **Create origin**:

- Origin domain: paste the **Public IPv4 DNS** from step 5d. Protocol **HTTP only**, HTTP port 80. Name `api`.
- Response timeout 60 s, keep-alive timeout 60 s.
- **Add custom header**: header name `X-Origin-Verify`, value = the exact `ORIGIN_SECRET` value from the box's `.env` (step 6:
  `grep '^ORIGIN_SECRET=' /opt/compineu/app/.env`; copy only what is after the `=`). No quotes, no spaces.
- **Create origin.**

**7d. Add the API behavior.** Tab **Behaviors**, **Create behavior**:

- Path pattern `/api/*`, origin `api`.
- Viewer protocol policy **HTTPS only**.
- Allowed HTTP methods **GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE**.
- Cache policy **CachingDisabled**. Origin request policy **AllViewer** (this forwards the login token).
  Response headers policy **SecurityHeadersPolicy**.
- Compress objects automatically **No** (keeps live updates unbuffered).
- **Create behavior.** Check that `/api/*` is listed above `Default (*)`.

**7e. Let CloudFront read the web bucket.** Copy the distribution id from the distribution page (it looks like
`E2ABC...`). Go to S3, the web bucket, **Permissions**, **Bucket policy**, **Edit**, replace the policy with this (swap
`DISTRIBUTION_ID`), and **Save changes**. You can instead use the policy from CloudFront's "Copy policy" banner and keep
the HTTPS rule too.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::compineu-web-157205473853-ap-south-1",
        "arn:aws:s3:::compineu-web-157205473853-ap-south-1/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "CloudFrontReadOnly",
      "Effect": "Allow",
      "Principal": { "Service": "cloudfront.amazonaws.com" },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::compineu-web-157205473853-ap-south-1/*",
      "Condition": {
        "ArnEquals": {
          "AWS:SourceArn": "arn:aws:cloudfront::157205473853:distribution/DISTRIBUTION_ID"
        }
      }
    }
  ]
}
```

If you would rather not look up the id, change the condition in the second statement to match any distribution in your own
account. Replace the whole `"Condition"` block of `CloudFrontReadOnly` with this. It stays safe (other accounts cannot
read the bucket) and needs no id:

```json
"Condition": {
  "ArnLike": { "AWS:SourceArn": "arn:aws:cloudfront::157205473853:distribution/*" }
}
```

The S3 policy editor expects an ARN-type operator for this key: `ArnEquals` for one id, `ArnLike` when the value has a
`*`. `StringEquals` and `StringLike` are flagged there. Do not delete the condition altogether: without it, a CloudFront distribution in any AWS account could read this bucket.

Write down the distribution **domain name** (`dxxxxxxxx.cloudfront.net`). Wait until its status is **Deployed**
(5 to 15 minutes).

## 8. Publish the frontend

The page is built on your PC and uploaded with clicks. This is the second and third terminal use: the build.

1. In the frontend project folder on your PC, create a file named `.env.production` containing exactly one line,
   with nothing after the equals sign:

   ```
   VITE_API_BASE_URL=
   ```

   Without it the page would call `http://localhost:8000` instead of your CloudFront address.
2. Run `npm ci` and then `npm run build`. The result is the `dist` folder.
3. S3, the web bucket `compineu-web-157205473853-ap-south-1`, **Upload**, **Add files** and **Add folder**: select
   everything **inside** `dist` (`index.html` and the `assets` folder, plus any other files), not the `dist` folder
   itself. **Upload**. For a later update, upload again and overwrite.
4. CloudFront, your distribution, tab **Invalidations**, **Create invalidation**, object path `/*`, **Create**. Do this
   after every upload so visitors get the new files.

## 9. Check that everything is connected

| Check | How | Expect |
|---|---|---|
| App loads | open `https://dxxxxxxxx.cloudfront.net` | The sign-in page with the brand panel |
| API through CloudFront | open `https://dxxxxxxxx.cloudfront.net/api/health` in the browser | `{"status":"ok","postgres":"ok"}` |
| Login | `admin@compineu.dev` and the `ADMIN_PASSWORD` value | The dashboard |
| Sign-up page | `https://dxxxxxxxx.cloudfront.net/signup` | The create-account form (it makes **admin** accounts) |
| CloudWatch logs | CloudWatch, Logs, Log management, `/compineu/prod` | Streams `api`, `nginx`, `postgres` |
| Observability page | sign in as admin, open Observability | Charts, not an error |
| Host metrics | CloudWatch, Metrics, All metrics, namespace `compineu/EC2` | memory, swap, disk and CPU after a few minutes |
| S3 evidence (PB6) | replay S1 in the app, approve it with PB6, then S3, the evidence bucket, folder `incidents/` | An object with Object Lock mode **Compliance** |

Approving PB6 writes a locked object that **cannot be deleted before its retention date** (1 day here). Do it only when you
mean to.

Optional alarm, all clicks: CloudWatch, **Alarms**, **Create alarm**, **Select metric**, `compineu/EC2`, then
`mem_used_percent`, condition greater than 85 for 2 periods, and add an email notification.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `docker: command not found`, or `/opt/compineu/.bootstrapped` is missing | The user data did not run (it was empty at launch, or the instance had no internet). Save the script from step 5b as `/tmp/user-data.sh` on the box and run `sudo bash /tmp/user-data.sh` (2 to 4 minutes). Check with `docker --version`. |
| Session Manager button is grey | The IAM role is not attached or lacks `AmazonSSMManagedInstanceCore`, or the box has no internet. Attach the role (Actions, Security, Modify IAM role) and wait 5 minutes. |
| Page loads but sign-in or data fails (403 or 502) | The `X-Origin-Verify` header on the `api` origin differs from `ORIGIN_SECRET`, the `/api/*` behavior is missing or below the default one, or the security group lacks the CloudFront prefix list on port 80. |
| Blank page, or `/cases/1` shows an error | The page-route function is not attached to the default behavior, or was not published. |
| S3 `AccessDenied` XML in the browser | The web bucket policy is missing or has the wrong distribution id, or `index.html` was not uploaded. |
| The page calls localhost | The build was made without `.env.production`. Rebuild, upload again and invalidate. |
| `setup.sh` says `no .env here` or `missing in .env: <KEY>` | Create the file with the block in step 6, or add the named key. Run `bash infra/box/setup.sh --check-env` to list every problem by name. |
| `setup.sh` says a key has the wrong format | Follow the rules in step 3: letters and digits only for the random secrets, and exactly 43 characters plus `=` for `PII_ENCRYPTION_KEY`. |
| The app fails to start with an encryption key error | `PII_ENCRYPTION_KEY` is not exactly 43 letters or digits followed by `=`. Fix it in `.env`, then run `setup.sh --local-env --no-seed` again. |
| Database connection errors | `POSTGRES_PASSWORD` contains a symbol, or you changed it after the first start. Postgres keeps the first password it was created with, so after changing it you must also remove the old database volume (`docker volume rm compineu-prod_pgdata`, which wipes the demo data) and run `setup.sh --local-env` again. |
| Docker build killed or very slow | Out of memory. Use a larger instance type; the 2 GB swap file helps but is slow. |
| Cases fail with a Groq error | Free-tier rate limit (HTTP 429) or a wrong key. A paid key is safer for a live demo. |
| PB6 fails with "S3 refused the evidence write" | Wrong `EVIDENCE_BUCKET` or region in `/opt/compineu/app/.env`, or the bucket has no Object Lock. |
| Observability page error | The log group is missing or misspelt, or the role lacks the log-query permission. |

## Alternative: Parameter Store instead of a `.env` file

Parameter Store is free (Standard tier, SecureString with the default key; do not pick Advanced or a custom key) and
keeps the secrets outside the box. To use it, create these parameters in Systems Manager, Parameter Store, all
**SecureString**, named `/compineu/prod/<NAME>`: `JWT_SECRET_KEY`, `PII_ENCRYPTION_KEY`, `POSTGRES_PASSWORD`,
`ORIGIN_SECRET`, `ADMIN_PASSWORD`, `QA_PASSWORD`, `GROQ_API_KEY`, `GROQ_MODEL_HEAVY` and `GROQ_MODEL_LIGHT`, with the same
value rules as step 3. Add two more statements to the `compineu-app` policy in step 4:

```json
{
  "Sid": "ReadOwnSecrets",
  "Effect": "Allow",
  "Action": ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"],
  "Resource": "arn:aws:ssm:ap-south-1:157205473853:parameter/compineu/*"
},
{
  "Sid": "DecryptSecretsViaSsmOnly",
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": { "StringEquals": { "kms:ViaService": "ssm.ap-south-1.amazonaws.com" } }
}
```

Then on the box skip the `.env` block, export `AWS_REGION=ap-south-1`, `SSM_PREFIX=/compineu/prod`,
`LOG_GROUP=/compineu/prod`, `EVIDENCE_BUCKET=compineu-evidence-157205473853-ap-south-1` and
`APP_URL=https://dxxxxxxxx.cloudfront.net`, and run `bash infra/box/setup.sh` without `--local-env`.

## Cost and cleanup

About $25 to $35 a month for the box, its disk and the Elastic IP (see [README.md](README.md)), plus Groq usage. When
you are done: stop or terminate the instance, release the Elastic IP, disable and delete the CloudFront distribution.
Locked evidence objects keep their bucket alive until the retention date passes.
