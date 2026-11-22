"""The avatar type check: PNG and JPEG are accepted by their signature only."""

from app.api.routers.auth import avatar_type_of


def test_avatar_accepts_png_and_jpeg_by_signature_only() -> None:
    assert avatar_type_of(b"\x89PNG\r\n\x1a\n" + b"rest") == "image/png"
    assert avatar_type_of(b"\xff\xd8\xff\xe0" + b"rest") == "image/jpeg"
    assert avatar_type_of(b"GIF89a....") is None
    assert avatar_type_of(b"<html>") is None
    assert avatar_type_of(b"") is None
