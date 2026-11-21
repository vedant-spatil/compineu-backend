from fastapi import APIRouter
from sqlalchemy import text

from app.db.session import engine

router = APIRouter(prefix="/api", tags=["health"])


def _check_db() -> str:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:  # noqa: BLE001 - report any failure
        return f"error: {type(exc).__name__}"


@router.get("/health")
def health() -> dict[str, str]:
    # PolicyGuard runs on Postgres alone: the AML Neo4j and yente checks are removed.
    return {"status": "ok", "postgres": _check_db()}
