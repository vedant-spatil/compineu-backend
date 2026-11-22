# compineu backend

FastAPI API, LangGraph case workflow, detectors, mock portal and AWS infra for compineu. The project overview, demo
scenarios and the full run and test commands are in the workspace [README](../README.md). Repo rules are in
[CLAUDE.md](CLAUDE.md) and the context docs in `markdown/` (runbook, architecture, bugs, updates).

## Setup

```bash
cp .env.example .env            # fill POSTGRES_PASSWORD, DATABASE_URL, GROQ_API_KEY, PII_ENCRYPTION_KEY, JWT_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # PII_ENCRYPTION_KEY
python -c "import secrets; print(secrets.token_urlsafe(48))"                                  # JWT_SECRET_KEY
uv sync --extra dev
python -m spacy download en_core_web_lg --no-deps   # Presidio model
```

## Run

```bash
docker compose up -d postgres                       # Postgres 16: user and db compineu
uv run alembic upgrade head                         # head: 0012_portal_fields
COMPINEU_PASSWORD='<12+ chars>' uv run python -m app.cli.create_user --email admin@compineu.dev --role admin
uv run python -m app.ingest.pg_generate --out data/policyguard    # synthetic world, seed 42
uv run python -m app.ingest.pg_load data/policyguard --reset
uv run uvicorn app.main:app --port 8000
```

## Tests

Run them in Ubuntu (WSL). Native libraries do not load from the `\\wsl.localhost` share with Windows Python.

```bash
UV_PROJECT_ENVIRONMENT=$HOME/.venvs/policyguard uv run --extra dev python -m pytest tests/unit -q
```
