"""
SAML2 SSO service for SP-initiated authentication.

Wraps python3-saml to build AuthnRequest and validate IdP responses.
Configuration is driven entirely by app.config.settings.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Request

from app.config import settings

logger = logging.getLogger(__name__)


def _get_saml_settings(request: Request) -> dict[str, Any]:
    """
    Build the python3-saml settings dict from app config + current request.

    The SP ACS URL is derived from the request origin unless explicitly
    configured via SAML_SP_ACS_URL.
    """
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
    base_url = f"{scheme}://{host}"

    sp_acs_url = settings.saml_sp_acs_url or f"{base_url}/api/v1/auth/saml/acs"

    return {
        "strict": True,
        "debug": settings.debug,
        "sp": {
            "entityId": settings.saml_sp_entity_id,
            "assertionConsumerService": {
                "url": sp_acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        },
        "idp": {
            "entityId": settings.saml_idp_entity_id or "",
            "singleSignOnService": {
                "url": settings.saml_idp_sso_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": settings.saml_idp_slo_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": settings.saml_idp_x509_cert or "",
        },
        "security": {
            "authnRequestsSigned": False,
            "wantAssertionsSigned": True,
            "wantNameIdEncrypted": False,
        },
    }


def prepare_saml_request(request: Request) -> dict[str, Any]:
    """
    Convert a FastAPI Request into the dict that python3-saml expects.
    """
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": {},
    }


async def prepare_saml_request_with_post(request: Request) -> dict[str, Any]:
    """
    Convert a FastAPI Request with form POST data for ACS callback.
    """
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))
    form = await request.form()
    return {
        "https": "on" if scheme == "https" else "off",
        "http_host": host,
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": dict(form),
    }


def get_saml_auth(request: Request, request_data: dict[str, Any] | None = None):
    """
    Instantiate a OneLogin_Saml2_Auth object.

    Raises ImportError if python3-saml is not installed.
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth

    req_data = request_data or prepare_saml_request(request)
    saml_settings = _get_saml_settings(request)
    return OneLogin_Saml2_Auth(req_data, saml_settings)
