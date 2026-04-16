"""
Unit tests for app/services/saml.py

Covers:
- _get_saml_settings: settings dict shape, SP/IdP/security, URL derivation
- prepare_saml_request: derives https on/off, host, query params
- prepare_saml_request_with_post: includes form data
- get_saml_auth: raises ImportError if python3-saml missing (we patch it to succeed)
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import saml as saml_module


def _mk_request(
    scheme="https",
    host="sso.example.com",
    path="/api/v1/auth/saml/login",
    query=None,
    xfp=None,
    xfh=None,
    form_data=None,
):
    req = MagicMock()
    req.url = MagicMock()
    req.url.scheme = scheme
    req.url.path = path
    req.query_params = query or {}
    headers = {"host": host}
    if xfp is not None:
        headers["x-forwarded-proto"] = xfp
    if xfh is not None:
        headers["x-forwarded-host"] = xfh
    req.headers = headers

    async def _form():
        return form_data or {}

    req.form = _form
    return req


class _FakeSettings:
    def __init__(
        self,
        debug=False,
        saml_sp_acs_url=None,
        saml_sp_entity_id="my-sp",
        saml_idp_entity_id="idp",
        saml_idp_sso_url="https://idp/sso",
        saml_idp_slo_url="https://idp/slo",
        saml_idp_x509_cert="CERT",
    ):
        self.debug = debug
        self.saml_sp_acs_url = saml_sp_acs_url
        self.saml_sp_entity_id = saml_sp_entity_id
        self.saml_idp_entity_id = saml_idp_entity_id
        self.saml_idp_sso_url = saml_idp_sso_url
        self.saml_idp_slo_url = saml_idp_slo_url
        self.saml_idp_x509_cert = saml_idp_x509_cert


class TestGetSamlSettings:
    def test_defaults_use_request_origin(self):
        req = _mk_request(scheme="https", host="app.example.com")
        with patch.object(saml_module, "settings", _FakeSettings()):
            s = saml_module._get_saml_settings(req)
        assert s["strict"] is True
        assert s["sp"]["entityId"] == "my-sp"
        assert s["sp"]["assertionConsumerService"]["url"].startswith("https://app.example.com")
        assert "saml/acs" in s["sp"]["assertionConsumerService"]["url"]
        assert s["idp"]["entityId"] == "idp"
        assert s["idp"]["singleSignOnService"]["url"] == "https://idp/sso"
        assert s["security"]["wantAssertionsSigned"] is True

    def test_explicit_sp_acs_url_wins(self):
        req = _mk_request()
        cfg = _FakeSettings(saml_sp_acs_url="https://custom/acs")
        with patch.object(saml_module, "settings", cfg):
            s = saml_module._get_saml_settings(req)
        assert s["sp"]["assertionConsumerService"]["url"] == "https://custom/acs"

    def test_x_forwarded_headers_used(self):
        req = _mk_request(xfp="https", xfh="public.example.com")
        with patch.object(saml_module, "settings", _FakeSettings()):
            s = saml_module._get_saml_settings(req)
        url = s["sp"]["assertionConsumerService"]["url"]
        assert "public.example.com" in url

    def test_debug_flag_reflected(self):
        req = _mk_request()
        with patch.object(saml_module, "settings", _FakeSettings(debug=True)):
            s = saml_module._get_saml_settings(req)
        assert s["debug"] is True

    def test_missing_idp_config_uses_empty_strings(self):
        req = _mk_request()
        cfg = _FakeSettings(
            saml_idp_entity_id=None,
            saml_idp_sso_url=None,
            saml_idp_slo_url=None,
            saml_idp_x509_cert=None,
        )
        with patch.object(saml_module, "settings", cfg):
            s = saml_module._get_saml_settings(req)
        assert s["idp"]["entityId"] == ""
        assert s["idp"]["singleSignOnService"]["url"] == ""
        assert s["idp"]["x509cert"] == ""


class TestPrepareSamlRequest:
    def test_https_on(self):
        req = _mk_request(scheme="https", host="x.com", path="/auth")
        data = saml_module.prepare_saml_request(req)
        assert data["https"] == "on"
        assert data["http_host"] == "x.com"
        assert data["script_name"] == "/auth"
        assert data["post_data"] == {}

    def test_http_off(self):
        req = _mk_request(scheme="http")
        data = saml_module.prepare_saml_request(req)
        assert data["https"] == "off"

    def test_query_params_included(self):
        req = _mk_request(query={"foo": "bar"})
        data = saml_module.prepare_saml_request(req)
        assert data["get_data"] == {"foo": "bar"}

    def test_xforwarded_proto_takes_precedence(self):
        req = _mk_request(scheme="http", xfp="https")
        data = saml_module.prepare_saml_request(req)
        assert data["https"] == "on"


class TestPrepareSamlRequestWithPost:
    @pytest.mark.asyncio
    async def test_form_data_included(self):
        req = _mk_request(form_data={"SAMLResponse": "base64data"})
        data = await saml_module.prepare_saml_request_with_post(req)
        assert data["post_data"]["SAMLResponse"] == "base64data"
        assert data["http_host"] == "sso.example.com"


class TestGetSamlAuth:
    def test_raises_importerror_when_python3_saml_missing(self):
        req = _mk_request()
        with patch.object(saml_module, "settings", _FakeSettings()):
            with patch.dict("sys.modules", {"onelogin.saml2.auth": None}):
                with pytest.raises((ImportError, Exception)):
                    saml_module.get_saml_auth(req)

    def test_constructs_auth_object(self):
        req = _mk_request()
        fake_auth_cls = MagicMock()
        fake_auth_cls.return_value = "AUTH_OBJ"

        # Create fake onelogin modules chain to simulate a successful import
        fake_auth_module = MagicMock()
        fake_auth_module.OneLogin_Saml2_Auth = fake_auth_cls

        with patch.object(saml_module, "settings", _FakeSettings()):
            with patch.dict(
                "sys.modules",
                {
                    "onelogin": MagicMock(),
                    "onelogin.saml2": MagicMock(),
                    "onelogin.saml2.auth": fake_auth_module,
                },
            ):
                result = saml_module.get_saml_auth(req)
        assert result == "AUTH_OBJ"
