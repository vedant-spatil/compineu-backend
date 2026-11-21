# HANDOFF: PolicyGuard AI (read this first, you have no chat history)

Written 20 Nov 2026 about 16:55 IST by the session that built the AWS side. You are taking over from another AI session on
another account. You can read the code and this file, nothing else. Everything you need to continue is here; where a fact
could not be verified, it says so.

**Deadlines (IST, today):** code freeze **17:00**, presentation and defense **17:00 to 17:45**, submit about 17:45.
Event: AI Forge 2026, SEESEC x AWS, Insurance and InsurTech track, team Mystical Productions. If you read this after
17:00, the job is: no new features. Only fix what is broken, keep the demo working, help rehearse.

---

## 0. Your first 10 minutes

1. `git fetch --all && git log --oneline -15 origin/main` in each repo (section 2). Know what is on `main` versus what is deployed.
2. Check the live system: `curl -s https://d2qe22rm1i2e6w.cloudfront.net/api/health` should return `{"status":"ok","postgres":"ok"}`.
3. Ask the human for: the hackathon AWS credentials (profile name `hackathon`, account `389070778843`, region `ap-south-1`),
   push access to GitHub (repos under user `Sumaniac28`), and the demo admin password. **Never print or commit secrets.**
4. Run the demo smoke test (section 6) once so you know what "working" looks like.
5. Read section 9 (what is open) and ask the human which of those they want you to take.

---

## 1. What the product is, and the demo story

PolicyGuard AI watches **insurance agents and TPA partner API keys** that read or export policyholder data outside their
authorised portfolio, investigates with GenAI, and runs containment playbooks **only after a human approves**.
Principle: **detection is code, GenAI is judgment, humans decide.**

It was built by reusing the team's own working AML Copilot (FastAPI, LangGraph with a human-approval interrupt, Bedrock client,
PII tokenisation, append-only audit trail, React UI) and replacing the AML domain with insurance logic. Say this on the
provenance slide: "we reused our AML investigation engine; everything insurance-specific was built today".

**Demo story, "an agent's bad night" (scenario S1):** agent AG-1147 opens 1,840 health-claim records outside his portfolio at
night from a new device and city, and exports 1,200 rows. An incident opens within seconds and climbs to critical (88.7); the
AI writes an evidence-cited report with a CERT-In draft and a DPDP-aligned draft; the analyst approves PB1 (suspend) and PB6
(preserve evidence); the agent's next request gets a **403**; the evidence lands in an **S3 Object Lock** bucket.
Then the GenAI proof: **Anita** (covering Priya on approved leave, ticket written by the manager) is **auto-resolved with
reasons** (S1b); **Dev** (wrote his own "approved" ticket) is **refused and promoted** (S1c). Then the quality screen.

Wording rules: say "DPDP-aligned readiness" (Rule 7, in force from 13 May 2027), never "compliant". Every draft says
"DRAFT - requires DPO review".

---

## 2. Repositories, branches, who owns what

Three private GitHub repos under `Sumaniac28`; local clones in `C:\seesec\policyguard\` (Windows, Git Bash).

| Repo | Folder | What | Deployed by |
|---|---|---|---|
| `policyguard-backend` | `neu-backend` | FastAPI API, workflow, detectors, generator, portal, infra | `bash infra/ship.sh` |
| `policyguard-frontend` | `neu-frontend` | React + Tailwind + React Query + Recharts + Cytoscape | `bash deploy/ship-web.sh` |
| `policyguard-notebook` | `neu-notebook` | Old AML ML notebooks. **Not used today.** | never |

Teammates (each has their own AI session and works on branches, then Sumit merges to `main` and deploys):

| Person | Owns |
|---|---|
| **Sumit** (the human you work for) | AWS, deploy, data generator, mock portal, replay, PB6 evidence helper, merges to `main` |
| **Raghav** | `migrations/`, models, `app/ingest/pg_rules.py` (detectors), `risk.py`, `detection.py` (`process_actor`), `playbooks.py`, `routers/quality.py`, `routers/cases.py` decision part, `dashboard.py` |
| **Bhavya** | `app/orchestration/*` (graph, prompts, routing, assembly, corroboration), `app/agents/agents.py`, `app/services/pg_data.py`, `llm.py`, `pii.py`, golden-set eval |
| **Krish** | the whole frontend, the control catalog JSON, the deck |

Rule from `CLAUDE.md`: stay in your lane. If you need a change in someone else's file, write down the exact change for the
human to pass on. Branches in the backend: `main` (deployed), `raghav/*`, `sumit/ai-data-0011` (Bhavya works here),
`bhavya/ai-workflow` (stale, ignore).

---

## 3. Architecture, one screen

```
Browser -> CloudFront (HTTPS, security headers)
            |-- /*      -> S3 web bucket (private, React build, via Origin Access Control)
            |-- /api/*  -> EC2 (Ubuntu 24.04, t3a.large, no SSH) :80 only from CloudFront, header X-Origin-Verify checked by nginx
                           nginx -> FastAPI (api) -> Postgres 16 (container, encrypted EBS)
EC2 instance role (no keys): Bedrock (2 models), S3 evidence bucket (put, no delete), SSM secrets, CloudWatch Logs.
```

Data flow of one incident: **mock portal / partner API** (writes `access_events`) -> **`detection.process_actor(actor, now)`**
(detectors, risk, alert upsert, opens or escalates a case) -> **LangGraph workflow** `triage -> load_context ->
[evidence | justification | classify] -> route -> (auto_resolve | report_writer -> await_human -> finalize)` -> human
decision (`POST /api/cases/{id}/decision` with `playbooks`) -> `finalize` runs `run_playbooks` (PB1 disables the agent
credential, PB2 disables the partner key, PB6 writes the evidence to S3 Object Lock, PB7 notifies).

Key design facts:
- **Code decides whether proof exists.** `check_corroboration` (pure code) tests leave/transfer/assignment records; the model
  explains, and `apply_justify_guards` overrides any "justified" without passing proof. Ticket text is untrusted data.
- **The audit table `case_events` is append-only** (database trigger blocks UPDATE, DELETE, TRUNCATE). The demo reset marks
  cases `superseded`; it can never erase the trail.
- **Names never reach the model.** Policyholders become `PH_###` tokens before the call; output is scrubbed with Presidio
  (agent/key ids are protected from the scrub). Revealing names is a separate audited endpoint.
- **Models** (Bedrock, ap-south-1): heavy `global.anthropic.claude-sonnet-4-6`, light `in.anthropic.claude-haiku-4-5-20251001-v1:0`.
  Claude 5.x is **not enabled** in this hackathon account ("not available for this account"). Do not switch models.

---

## 4. AWS facts (verified)

- **Use the `hackathon` AWS CLI profile** (account `389070778843`, user `global-admin`, region `ap-south-1`). The human's `default`
  profile is a **personal account (157205473853): never deploy there.** Scripts accept `EXPECT_ACCOUNT=389070778843`.
- CloudFormation stack **`policyguard`** (`infra/policyguard.yaml`; created by `infra/deploy.sh`). Outputs:
  CloudFront `https://d2qe22rm1i2e6w.cloudfront.net` (dist `E1DD6HIEISNKYX`), EC2 `i-00b4b7aecc2e25e69`,
  buckets `policyguard-web-389070778843`, `policyguard-evidence-389070778843` (Object Lock COMPLIANCE, 1 day),
  `policyguard-artifacts-389070778843`, log group `/policyguard/prod`.
- **No SSH.** Shell access only via SSM Run Command (`aws ssm send-command`, document `AWS-RunShellScript`, which runs `/bin/sh`: write
  a script file and run it with `bash`). The deploy scripts do this for you.
- **Secrets** are SSM SecureStrings under `/policyguard/prod/` (`JWT_SECRET_KEY`, `PII_ENCRYPTION_KEY`, `POSTGRES_PASSWORD`,
  `ORIGIN_SECRET`, `ADMIN_PASSWORD`). The box writes `.env` from them with `infra/box/render-env.sh`. Demo admin user:
  `ciso@policyguard.demo`, role admin, password in SSM `/policyguard/prod/ADMIN_PASSWORD`.
- Org CloudTrail already records management events. GuardDuty, CloudWatch alarms, Bedrock Guardrails and AgentCore are **not** set up (optional, dropped).
- The evidence bucket is **Object Lock COMPLIANCE for 1 day**: objects cannot be deleted by anyone until retention ends, by design.
  The instance role is explicitly denied delete. Do not try to empty or delete that bucket.
- Teardown: `aws cloudformation delete-stack --stack-name policyguard` (the evidence bucket is retained on purpose; web and
  artifacts buckets must be emptied first). **Do not tear down before the human says the event is over.**

---

## 5. Deploy

```bash
# backend (from neu-backend): packages the working tree (tracked + new files, .gitignore applied), uploads to the artifacts
# bucket, and the box rebuilds the api image and restarts. ~1 min when cached.
AWS_PROFILE=hackathon bash infra/ship.sh
# frontend (from neu-frontend): build with same-origin API, sync to S3, invalidate CloudFront
AWS_PROFILE=hackathon bash deploy/ship-web.sh
# unit tests inside the real image on the box (laptop has no pytest/uv): see infra/demo or run the docker snippet used in history
```
Merge flow used today: teammates push branches; the human (or you) merges to `main` locally, ships, **verifies on AWS**, then pushes `main`.
The migration runs automatically when the api container starts (`alembic upgrade head`); head is `0012_portal_fields`. Next migration: `0013`.

Reload the synthetic world on the box (only if the database is empty): inside the api container,
`python -m app.ingest.pg_generate --out /tmp/pg && python -m app.ingest.pg_load /tmp/pg --reset` (about 10 seconds).

---

## 6. Test and demo commands

```bash
AWS_PROFILE=hackathon bash infra/demo/smoke.sh S1b S1c S1        # replay scenarios, wait, print what each case ended as; resets at the end
AWS_PROFILE=hackathon bash infra/demo/approve_e2e.sh S1 PB1,PB6,PB7 AG-1147    # replay, APPROVE with playbooks, prove 403 + S3 object, reset
AWS_PROFILE=hackathon bash infra/demo/approve_e2e.sh S2 PB2,PB6,PB7 PK-CARELINK  # partner-key version (NOT yet run, see section 9)
```
Both log in as the demo admin using the password from SSM at run time. API surface for the scenario console (admin JWT):
`POST /api/replay/{S1|S1b|S1c|S1d|S2|S5|D1..D4|EG1..EG8|EF1..EF5}?speed=60`, `POST /api/replay/reset`, `GET /api/replay/status`.
Other endpoints: `GET /api/quality`, `POST /api/cases/{id}/decision`, `GET /api/cases/{id}/sar` (the report), `GET /api/stream` (SSE).

### Scenario results verified on AWS today

| Scenario | Actor | Result |
|---|---|---|
| S1 bad night | AG-1147 | Incident, **88.7** (A1+A2+A3+A4), `awaiting_review`, 2 reruns on escalation |
| S1b genuine cover | AG-1033 covers AG-0932 | **auto_resolved**, cites LV-221 + TKT-4471 |
| S1c forged ticket | AG-1088 | promoted (`unjustified`), blockers `verdict_not_justified`, `corroboration_not_ok` |
| S1d forged ticket on real leave | AG-1120 | promoted |
| S5 ex-employee | AG-0577 | incident at exactly **60** (I1 floor + A2) |
| S2 TPA key from abroad | PK-CARELINK | critical **98.4** (P1+P2+P3) |
| D2 servicing-assignment cover | AG-1055 | A2 fires (42.9), AI auto-resolves citing the assignment |
| Approve S1 with PB1+PB6+PB7 | | 200; agent then gets **403**; S3 object `COMPLIANCE`; PB7 notification; **rerun after reset works** |
| `/api/quality` after S1 | | precision 1.0, recall 1.0, median time to detect 3.1 simulated min |

Detection windows use the **simulated clock**: the replay shifts each scenario to "now" and passes a simulated `now` to
`process_actor`. Never use the wall clock in detection or the workflow.

---

## 7. File map (backend)

| Path | What |
|---|---|
| `app/main.py` | router list; startup compiles the graph |
| `app/portal/service.py`, `store.py`, `replay.py`; `app/api/routers/portal.py`, `replay.py` | mock portal and partner API; replay and reset |
| `app/ingest/pg_generate.py`, `pg_load.py` | seed-42 world generator (stdlib only) and COPY loader |
| `app/ingest/pg_rules.py`, `app/services/risk.py`, `detection.py` | detectors A1-A4, I1, P1-P3; risk formula; `process_actor` |
| `app/orchestration/` | `graph.py`, `state.py`, `routing.py`, `assembly.py`, `corroboration.py`, `prompts.py`, `controls.py` |
| `app/agents/agents.py` | the workflow nodes |
| `app/services/pg_data.py`, `llm.py`, `pii.py`, `evidence.py`, `playbooks.py`, `audit.py` | data reads, Bedrock client, PII, PB6, playbooks, audit |
| `app/api/routers/cases.py`, `quality.py` | decision endpoint; quality page numbers |
| `app/evaluation/golden_set.py` | offline and live AI evaluation |
| `migrations/versions/0011_policyguard.py`, `0012_portal_fields.py` | schema |
| `infra/` | CloudFormation, deploy, ship, `box/render-env.sh`, `demo/*` scripts, `scripts/aws/00-preflight.sh` (account and Bedrock check) |
| `tests/unit/`, `tests/fixtures/pg_small/` | 324 pass on the box, 8 skipped (AML tests); small fixture with its README |
| `docs/policyguard/` (gitignored: use `git add -f`) | final build plan, Raghav's task file, Bhavya's brief and lane report |

Frontend: `src/features/{dashboard,alerts,cases,approvals,compliance,quality}`, `src/components/IncidentReportView.tsx`,
`src/data/controls.json` (the nine control ids), `src/api/report.ts` (report contract), `deploy/ship-web.sh`.

---

## 8. Gotchas that cost time today (do not rediscover them)

- **Git Bash on Windows rewrites `/...` arguments** (breaks SSM paths like `/policyguard/...`). Set `MSYS_NO_PATHCONV=1`. The Windows
  `aws.exe` needs Windows paths for files: use `cygpath -w`. GNU `tar` reads `C:` as a remote host: use `/c/...` paths.
- **Container logs go to CloudWatch (awslogs driver); `docker logs` is empty.** Use `aws logs filter-log-events --log-group-name /policyguard/prod`.
  The workflow node wrapper swallows exceptions into `case_events` (`kind=error`) without a traceback; reproduce on the box to see one.
- **`docs/` is in `.gitignore`**; new files there need `git add -f`.
- CRLF/LF: `.gitattributes` forces LF for scripts and configs. Warnings about "LF will be replaced by CRLF" are harmless.
- Windows laptops cannot import `app.ingest.alerts`, `sync.py` or `rebuild_alerts.py` (Unix-only `resource`); never import them from new code.
- The Claude Code auto-mode safety check sometimes denies `git push` and scripts that read SSM secrets. If a push is denied, do not
  work around it: ask the human to push.
- `agents.usual_start_hour` and `usual_end_hour` are **IST** while `access_events.ts` is **UTC**; convert before comparing.
- Timestamps in all new tables are naive UTC.
- Sonnet sometimes returns nested report sections as JSON strings; `assembly` decodes them and `report_writer` falls back to a
  code-only report if assembly fails.
- A `reset` supersedes active cases, deletes replayed events and restores agents and keys. Raghav's `detection` ignores a decided case whose events a reset deleted, so approve -> reset -> replay works (verified).

---

## 9. What is open (as of writing) and what to do about it

| Item | Owner | State |
|---|---|---|
| **Push `main` to GitHub** | Sumit | `main` was merged and deployed locally to AWS but a push was denied by the auto-mode check. Confirm `git log origin/main` matches what is live; if not, ask the human to run `git push origin main` in `neu-backend` |
| **S2 end-to-end approval with PB2** (`approve_e2e.sh S2 PB2,PB6,PB7 PK-CARELINK`) | Sumit/you | Not run yet. Expect 403 for the partner key after approval |
| **Raghav T11:** dashboard numbers (clocks running, records at risk, controls passing) | Raghav | Not on main; dashboard cards show "-" |
| **Golden-set live numbers for the slide** (`python -m app.evaluation.golden_set --live`) and where `/api/quality` reads them | Bhavya | Not run; offline passes |
| **Classifier quality:** the light model labels S1 `negligent` and S1c `benign_exception` (manifest says `malicious_insider`); it sees aggregates only | Bhavya | Known, low priority; a prompt hint would fix it |
| **Baseline days 3 -> 2** (`MIN_BASELINE_DAYS` in `corroboration.py`) | Bhavya/Sumit | Needed so S1b can auto-resolve on the loaded data; weakens one gate slightly. Be ready to explain it |
| **Control clause text** is Krish's paraphrase: check against the validated combined plan (sections 11 and 19) before any slide | Krish | Open. A wrong clause number is exactly what a compliance judge will catch |
| **Deck, screenshots, rehearsals, backup video** | Krish / everyone / Sumit | Not started or in progress; screenshots must come from the live system with Reset between scenarios |
| Bedrock Guardrail, CloudWatch alarms, AgentCore, RDS | | Dropped on purpose (cut list). Do not start them now |
| `neu-notebook`, XGBoost triage score | | Roadmap slide only ("trained on SageMaker as we did for AML"). Not shipped, because training on our own generated labels is circular |

Cut list if time is short (drop in this order): Guardrail, alarms, S5, quality page numbers (put them on a slide), compliance page.
**Never cut:** S1 end to end on AWS with Bedrock, S1b versus S1c, the approval with PB1 and PB6, the audit timeline, the clocks.

**Fallback demo if something breaks:** show the S1 replay, the incident with its report, S1b versus S1c, and the portal refusing
after `credential_enabled=false`; use the recorded backup video for the rest.

---

## 10. Pitch and defense anchors (6 minutes)

Hook: Star Health 2024 (largest standalone health insurer; a hacker claimed an insider's help; IRDAI later fined it for late
reporting). Problem: agents and POSPs sit outside IRDAI's cyber guideline scope, so the insurer must police them; cloud tools see
AWS calls, not record reads. Then the architecture slide, the live S1 (about 40 s at 60x), Anita/Dev, the accuracy screen,
the business case (runs in the insurer's own AWS account), the provenance slide, the close ("PolicyGuard watches the book of
business, so an insurer never learns about its breach from Telegram").

Likely questions and honest answers:
- *Did you build this today?* The insurance logic, yes; the engine underneath is ours from an AML project, which the rules allow.
- *Why EC2 and not serverless?* Containerised; the same images run on ECS Fargate and the workflow on AgentCore. We chose the path we had already tested for a 6-hour build.
- *Why LangGraph, not Step Functions?* Same pause-for-approval semantics; the Postgres checkpoint survives restarts; already tested.
- *Is the audit trail tamper-proof?* A database trigger refuses UPDATE/DELETE/TRUNCATE on it, and evidence is copied to S3 Object Lock in compliance mode. Even our demo reset cannot erase it.
- *Does the AI see names?* No: tokens before the call, scrub after; revealing names is a separate audited action.
- *Is the ML trained on your own fake labels?* We deliberately shipped no ML score today for that reason. Detection is rules plus baselines.
- *Why Sonnet 4.6 and not newer?* The 5.x models are not enabled in the hackathon account.
- Say plainly: Guardrails' PII filter does not see forced tool-call output, so PII protection is tokenise-then-scrub; a Guardrail ID was not added.

---

## 11. Do not

- Do not deploy to the personal AWS account, print secrets, or commit `.env`, keys or passwords.
- Do not delete or alter `case_events`, the evidence bucket, or the CloudFormation stack; do not "fix" the audit trigger.
- Do not re-enable Supabase, Neo4j Aura, Vercel, Groq, yente, Elasticsearch or OpenSanctions.
- Do not change the model IDs, the risk formula, or routing thresholds (`INCIDENT_THRESHOLD` 0.60, `TRIAGE_THRESHOLD` 0.40) without telling the human.
- Do not merge a teammate's branch without running the test suite on the box and one replay (`smoke.sh S1b S1c S1`).
- Do not make large changes after 17:00.
