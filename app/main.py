from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# The AML imports and projects routers are unhooked for PolicyGuard (their modules stay; see CLAUDE.md rule 5).
from app.api.routers import (
    auth,
    cases,
    health,
    notifications,
    observability,
    stream,
    users,
)
from app.api.routers import portal  # PolicyGuard mock portal + partner API (separate line: fewer merge conflicts)
from app.api.routers import replay  # PolicyGuard scenario console: replay and reset
from app.api.routers import quality  # PolicyGuard quality page (admin): detection precision, recall, time to detect
from app.config import get_settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Create LangGraph checkpoint tables once, before any request can start a case.
    from app.orchestration.graph import get_graph

    get_graph()
    # With TRIAGE_MODEL=xgb, warn now if the configured model run has no scores (cases would use rule scores).
    # Postgres only; no Neo4j.
    from app.services.triage_check import warn_if_no_scores

    warn_if_no_scores()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="AML Investigation Copilot", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT"],  # PUT: the profile picture upload (/api/auth/me/avatar)
        allow_headers=["Authorization", "Content-Type"],
    )
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(cases.router)
    app.include_router(users.router)
    app.include_router(notifications.router)
    app.include_router(stream.router)
    app.include_router(observability.router)
    app.include_router(portal.router)
    app.include_router(replay.router)
    app.include_router(quality.router)
    return app


app = create_app()
