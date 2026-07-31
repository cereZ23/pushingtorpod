"""
Regression test for the RequestValidationError handler in app.main.

Pydantic v2 embeds the raw ValueError raised by a custom field validator (e.g.
onboarding's password-strength check) inside each error's `ctx`. That object is
not JSON-serializable, so passing exc.errors() straight to JSONResponse made
json.dumps raise — turning a clean 422 into a generic 500 ("server error")
instead of telling the user the real reason. The handler must sanitize.
"""

import json
import pytest
from unittest.mock import MagicMock

from fastapi.exceptions import RequestValidationError

from app.main import validation_exception_handler


def _mk_request(path="/api/v1/onboarding/register", method="POST"):
    req = MagicMock()
    req.url = MagicMock()
    req.url.path = path
    req.method = method
    return req


@pytest.mark.asyncio
async def test_serializes_valueerror_in_ctx_without_500():
    """A custom-validator ValueError in ctx must not blow up serialization."""
    exc = MagicMock(spec=RequestValidationError)
    exc.errors = MagicMock(
        return_value=[
            {
                "type": "value_error",
                "loc": ("body", "password"),
                "msg": "Value error, Password must contain an uppercase letter",
                "input": "weak",
                # This is the part that used to crash json.dumps:
                "ctx": {"error": ValueError("Password must contain an uppercase letter")},
            }
        ]
    )

    resp = await validation_exception_handler(_mk_request(), exc)

    assert resp.status_code == 422
    # Body must be valid JSON (the old handler raised here at JSONResponse render).
    body = json.loads(resp.body.decode())
    assert body["error"] == "ValidationError"
    assert body["status_code"] == 422
    # Human-readable reason surfaced in `detail` (what the forms display).
    assert "password" in body["detail"].lower()
    # Sanitized error list — no leaked ValueError object.
    assert body["errors"][0]["field"] == "password"
    assert body["errors"][0]["type"] == "value_error"


@pytest.mark.asyncio
async def test_empty_errors_falls_back_to_generic_detail():
    exc = MagicMock(spec=RequestValidationError)
    exc.errors = MagicMock(return_value=[])

    resp = await validation_exception_handler(_mk_request(), exc)

    assert resp.status_code == 422
    body = json.loads(resp.body.decode())
    assert body["detail"] == "Request validation failed"
    assert body["errors"] == []
