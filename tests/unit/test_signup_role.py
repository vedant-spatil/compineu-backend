"""Sign-up registers every new account as an admin and returns an admin token."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.routers import auth
from app.auth.passwords import verify_password
from app.auth.tokens import decode_access_token


class FakeDb:
    """Just enough of a Session for signup(): an optional existing email, add and commit."""

    def __init__(self, existing: bool = False) -> None:
        self.existing = existing
        self.added: list = []
        self.committed = False

    def execute(self, _stmt):
        return SimpleNamespace(first=lambda: (1,) if self.existing else None)

    def add(self, obj) -> None:
        obj.id = 42  # the database would assign this on commit
        self.added.append(obj)

    def commit(self) -> None:
        self.committed = True


def _request(ip: str = "10.0.0.1"):
    return SimpleNamespace(client=SimpleNamespace(host=ip))


@pytest.fixture(autouse=True)
def _clear_rate_limit():
    auth._signup_hits.clear()
    yield
    auth._signup_hits.clear()


def test_signup_creates_an_admin() -> None:
    db = FakeDb()
    out = auth.signup(auth.SignupIn(email="new.person@example.com", password="a-long-password"), _request(), db)

    user = db.added[0]
    assert user.role == "admin" and auth.SIGNUP_ROLE == "admin"
    assert user.is_active is True and db.committed
    assert verify_password("a-long-password", user.password_hash)
    assert decode_access_token(out.access_token)["role"] == "admin"


def test_signup_never_creates_a_qa_user() -> None:
    db = FakeDb()
    auth.signup(auth.SignupIn(email="someone@example.com", password="another-long-one"), _request(), db)
    assert db.added[0].role != "qa"


def test_signup_still_refuses_an_existing_email() -> None:
    db = FakeDb(existing=True)
    with pytest.raises(HTTPException) as exc:
        auth.signup(auth.SignupIn(email="taken@example.com", password="a-long-password"), _request(), db)
    assert exc.value.status_code == 400 and db.added == []


def test_signup_is_still_rate_limited_per_ip() -> None:
    for i in range(auth.SIGNUP_MAX_PER_WINDOW):
        auth.signup(auth.SignupIn(email=f"u{i}@example.com", password="a-long-password"), _request(), FakeDb())
    with pytest.raises(HTTPException) as exc:
        auth.signup(auth.SignupIn(email="one-too-many@example.com", password="a-long-password"), _request(), FakeDb())
    assert exc.value.status_code == 429
