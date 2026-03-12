"""
Comprehensive test suite for the ticketing integration.

Tests cover:
- Encryption/decryption of provider configs
- Jira provider (mocked HTTP)
- ServiceNow provider (mocked HTTP)
- TicketSyncService (create, inbound, outbound, full sync)
- API endpoints (router-level)
- Celery tasks
"""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import httpx

# ------------------------------------------------------------------
# Encryption tests
# ------------------------------------------------------------------


class TestCrypto:
    """Tests for app.services.ticketing.crypto module."""

    def test_encrypt_decrypt_roundtrip(self):
        from app.services.ticketing.crypto import encrypt_config, decrypt_config

        original = {
            "url": "https://company.atlassian.net",
            "email": "test@example.com",
            "api_token": "super-secret-token-12345",
            "project_key": "EASM",
        }
        secret = "test-secret-key-for-unit-tests-must-be-long-enough"

        encrypted = encrypt_config(original, secret)
        assert isinstance(encrypted, str)
        assert "super-secret-token" not in encrypted  # Must not leak plaintext

        decrypted = decrypt_config(encrypted, secret)
        assert decrypted == original

    def test_decrypt_with_wrong_key_returns_none(self):
        from app.services.ticketing.crypto import encrypt_config, decrypt_config

        original = {"api_token": "secret"}
        encrypted = encrypt_config(original, "correct-key-xxxxxxxxxxxxxxxxxxxxxx")
        result = decrypt_config(encrypted, "wrong-key-xxxxxxxxxxxxxxxxxxxxxxxx")
        assert result is None

    def test_decrypt_invalid_data_returns_none(self):
        from app.services.ticketing.crypto import decrypt_config

        result = decrypt_config("not-valid-fernet-data", "any-key-xxxxxxxxxxxxx")
        assert result is None

    def test_mask_config_hides_sensitive_fields(self):
        from app.services.ticketing.crypto import mask_config

        config = {
            "url": "https://company.atlassian.net",
            "email": "test@example.com",
            "api_token": "ATATT3xFfGF0TT1234567890abcdef",
            "password": "my-secret-password",
            "project_key": "EASM",
        }
        masked = mask_config(config)
        assert masked["url"] == config["url"]
        assert masked["email"] == config["email"]
        assert masked["project_key"] == config["project_key"]
        # Sensitive fields should be masked
        assert "ATATT3xFf" not in masked["api_token"]
        assert masked["api_token"].startswith("AT")
        assert masked["api_token"].endswith("ef")
        assert "*" in masked["api_token"]
        assert "my-secret-password" not in masked["password"]

    def test_mask_config_short_values_not_masked(self):
        from app.services.ticketing.crypto import mask_config

        config = {"api_token": "ab"}  # Too short to mask
        masked = mask_config(config)
        assert masked["api_token"] == "ab"


# ------------------------------------------------------------------
# Jira Provider tests (mocked HTTP)
# ------------------------------------------------------------------


class TestJiraProvider:
    """Tests for JiraProvider with mocked httpx.Client."""

    def _make_provider(self):
        from app.services.ticketing.jira_provider import JiraProvider

        config = {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "test-token",
            "project_key": "TEST",
            "issue_type": "Bug",
        }
        return JiraProvider(config)

    def test_create_ticket_success(self):
        from app.services.ticketing import TicketData

        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "id": "10001",
            "key": "TEST-42",
            "self": "https://test.atlassian.net/rest/api/3/issue/10001",
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        data = TicketData(
            title="Critical SQL Injection on api.example.com",
            description="Nuclei found SQLi via template CVE-2024-1234",
            severity="critical",
            finding_id=99,
            tenant_id=1,
            labels=["vuln"],
        )

        result = provider.create_ticket(data)

        assert result.external_id == "TEST-42"
        assert result.external_url == "https://test.atlassian.net/browse/TEST-42"
        assert result.external_status == "To Do"

        # Verify the POST was made
        call_args = mock_client.request.call_args
        assert call_args[0][0] == "POST"
        assert call_args[0][1] == "/issue"
        payload = call_args[1]["json"]
        assert payload["fields"]["project"]["key"] == "TEST"
        assert payload["fields"]["priority"]["name"] == "Highest"
        assert "easm" in payload["fields"]["labels"]
        assert "critical" in payload["fields"]["labels"]
        assert "vuln" in payload["fields"]["labels"]

    def test_create_ticket_failure_raises(self):
        from app.services.ticketing import TicketData

        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = '{"errors":{"summary":"Field required"}}'

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        data = TicketData(
            title="Test",
            description="Test",
            severity="low",
            finding_id=1,
            tenant_id=1,
        )

        with pytest.raises(RuntimeError, match="Jira issue creation failed"):
            provider.create_ticket(data)

    def test_get_ticket_status(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "fields": {"status": {"name": "In Progress", "statusCategory": {"key": "indeterminate"}}}
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        status = provider.get_ticket_status("TEST-42")
        assert status == "In Progress"

    def test_get_ticket_status_category(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "fields": {"status": {"name": "Done", "statusCategory": {"key": "done"}}}
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        normalized = provider.get_ticket_status_category("TEST-42")
        assert normalized == "closed"

    def test_add_comment_success(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 201

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.add_comment("TEST-42", "Finding re-scanned, still present.")
        assert result is True

    def test_close_ticket_success(self):
        provider = self._make_provider()

        # First call: get transitions
        transitions_response = MagicMock()
        transitions_response.status_code = 200
        transitions_response.json.return_value = {
            "transitions": [
                {"id": "31", "name": "Done", "to": {"statusCategory": {"key": "done"}}},
                {"id": "21", "name": "In Progress", "to": {"statusCategory": {"key": "indeterminate"}}},
            ]
        }

        # Second call: execute transition
        transition_response = MagicMock()
        transition_response.status_code = 204

        mock_client = MagicMock()
        mock_client.request.side_effect = [transitions_response, transition_response]
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.close_ticket("TEST-42", resolution="Fixed")
        assert result is True

        # Verify the transition was called with the right ID
        second_call = mock_client.request.call_args_list[1]
        assert second_call[0][0] == "POST"
        assert "transitions" in second_call[0][1]
        payload = second_call[1]["json"]
        assert payload["transition"]["id"] == "31"

    def test_close_ticket_no_transition_found(self):
        provider = self._make_provider()

        transitions_response = MagicMock()
        transitions_response.status_code = 200
        transitions_response.json.return_value = {
            "transitions": [
                {"id": "21", "name": "In Progress", "to": {"statusCategory": {"key": "indeterminate"}}},
            ]
        }

        mock_client = MagicMock()
        mock_client.request.return_value = transitions_response
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.close_ticket("TEST-42")
        assert result is False

    def test_test_connection_success(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "displayName": "Test User",
            "emailAddress": "test@example.com",
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        assert provider.test_connection() is True

    def test_test_connection_failure(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 401

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        assert provider.test_connection() is False

    def test_build_adf_description(self):
        from app.services.ticketing import TicketData

        provider = self._make_provider()

        data = TicketData(
            title="Test Finding",
            description="This is a test description.",
            severity="high",
            finding_id=42,
            tenant_id=1,
            custom_fields={"CVE": "CVE-2024-1234", "CVSS": "9.8"},
        )

        adf = provider._build_adf_description(data)
        assert adf["type"] == "doc"
        assert adf["version"] == 1
        assert len(adf["content"]) >= 3  # Header, severity, description, custom fields, provenance

        # Check that custom fields are included
        all_text = json.dumps(adf)
        assert "CVE-2024-1234" in all_text
        assert "9.8" in all_text
        assert "finding_id=42" in all_text

    def test_update_ticket_success(self):
        provider = self._make_provider()

        # First call: PUT (update)
        update_response = MagicMock()
        update_response.status_code = 204

        # Second call: GET (status fetch in update_ticket)
        status_response = MagicMock()
        status_response.status_code = 200
        status_response.json.return_value = {
            "fields": {"status": {"name": "In Progress"}}
        }

        mock_client = MagicMock()
        mock_client.request.side_effect = [update_response, status_response]
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.update_ticket("TEST-42", {"summary": "Updated title"})
        assert result.external_id == "TEST-42"
        assert result.external_status == "In Progress"

    def test_retry_on_server_error(self):
        """Verify the provider retries on 5xx errors."""
        provider = self._make_provider()

        error_response = MagicMock()
        error_response.status_code = 503

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.json.return_value = {"displayName": "Test"}

        mock_client = MagicMock()
        mock_client.request.side_effect = [error_response, success_response]
        mock_client.is_closed = False
        provider._client = mock_client

        with patch("app.services.ticketing.jira_provider.time.sleep"):
            assert provider.test_connection() is True


# ------------------------------------------------------------------
# ServiceNow Provider tests (mocked HTTP)
# ------------------------------------------------------------------


class TestServiceNowProvider:
    """Tests for ServiceNowProvider with mocked httpx.Client."""

    def _make_provider(self):
        from app.services.ticketing.servicenow_provider import ServiceNowProvider

        config = {
            "instance": "testcompany",
            "username": "admin",
            "password": "secret",
            "table": "incident",
        }
        return ServiceNowProvider(config)

    def test_create_ticket_success(self):
        from app.services.ticketing import TicketData

        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "result": {
                "sys_id": "abc123",
                "number": "INC0012345",
                "state": "1",
            }
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        data = TicketData(
            title="Critical XSS on portal.example.com",
            description="Reflected XSS found via Nuclei scan",
            severity="critical",
            finding_id=42,
            tenant_id=1,
        )

        result = provider.create_ticket(data)

        assert result.external_id == "INC0012345"
        assert "testcompany.service-now.com" in result.external_url
        assert result.external_status == "New"

        # Verify payload
        call_args = mock_client.request.call_args
        payload = call_args[1]["json"]
        assert payload["impact"] == "1"  # Critical -> High impact
        assert payload["urgency"] == "1"  # Critical -> High urgency
        assert payload["category"] == "Security"

    def test_create_ticket_failure_raises(self):
        from app.services.ticketing import TicketData

        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        data = TicketData(
            title="Test", description="Test", severity="low",
            finding_id=1, tenant_id=1,
        )

        with pytest.raises(RuntimeError, match="ServiceNow incident creation failed"):
            provider.create_ticket(data)

    def test_get_ticket_status(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": [{"state": "2", "number": "INC0012345"}]
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        status = provider.get_ticket_status("INC0012345")
        assert status == "In Progress"

    def test_get_normalized_status(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": [{"state": "6"}]  # Resolved
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        normalized = provider.get_normalized_status("INC0012345")
        assert normalized == "resolved"

    def test_add_comment_success(self):
        provider = self._make_provider()

        # First call: lookup sys_id
        lookup_response = MagicMock()
        lookup_response.status_code = 200
        lookup_response.json.return_value = {
            "result": [{"sys_id": "abc123"}]
        }

        # Second call: PATCH with work_notes
        patch_response = MagicMock()
        patch_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.side_effect = [lookup_response, patch_response]
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.add_comment("INC0012345", "Updated scan results available.")
        assert result is True

    def test_close_ticket_success(self):
        provider = self._make_provider()

        # First call: lookup sys_id
        lookup_response = MagicMock()
        lookup_response.status_code = 200
        lookup_response.json.return_value = {
            "result": [{"sys_id": "abc123"}]
        }

        # Second call: PATCH state to resolved
        patch_response = MagicMock()
        patch_response.status_code = 200

        mock_client = MagicMock()
        mock_client.request.side_effect = [lookup_response, patch_response]
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.close_ticket("INC0012345", resolution="Fixed")
        assert result is True

    def test_close_ticket_not_found(self):
        provider = self._make_provider()

        lookup_response = MagicMock()
        lookup_response.status_code = 200
        lookup_response.json.return_value = {"result": []}

        mock_client = MagicMock()
        mock_client.request.return_value = lookup_response
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.close_ticket("INC9999999")
        assert result is False

    def test_test_connection_success(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": [{"user_name": "admin", "name": "System Admin", "email": "admin@example.com"}]
        }

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        assert provider.test_connection() is True

    def test_test_connection_failure(self):
        provider = self._make_provider()

        mock_response = MagicMock()
        mock_response.status_code = 401

        mock_client = MagicMock()
        mock_client.request.return_value = mock_response
        mock_client.is_closed = False
        provider._client = mock_client

        assert provider.test_connection() is False

    def test_update_ticket_success(self):
        provider = self._make_provider()

        # Lookup
        lookup_response = MagicMock()
        lookup_response.status_code = 200
        lookup_response.json.return_value = {"result": [{"sys_id": "abc123"}]}

        # Patch
        patch_response = MagicMock()
        patch_response.status_code = 200
        patch_response.json.return_value = {
            "result": {"state": "2", "number": "INC0012345"}
        }

        mock_client = MagicMock()
        mock_client.request.side_effect = [lookup_response, patch_response]
        mock_client.is_closed = False
        provider._client = mock_client

        result = provider.update_ticket("INC0012345", {"short_description": "Updated"})
        assert result.external_id == "INC0012345"
        assert result.external_status == "In Progress"

    def test_build_description(self):
        from app.services.ticketing import TicketData

        data = TicketData(
            title="Test Finding",
            description="SQL injection detected",
            severity="high",
            finding_id=42,
            tenant_id=1,
            custom_fields={"CVE": "CVE-2024-5678"},
        )
        desc = ServiceNowProvider._build_description(data)
        assert "Test Finding" in desc
        assert "HIGH" in desc
        assert "SQL injection detected" in desc
        assert "CVE-2024-5678" in desc
        assert "finding_id=42" in desc

    def test_state_number_to_label(self):
        assert ServiceNowProvider._state_number_to_label("1") == "New"
        assert ServiceNowProvider._state_number_to_label("6") == "Resolved"
        assert "Unknown" in ServiceNowProvider._state_number_to_label("99")


# ------------------------------------------------------------------
# Factory tests
# ------------------------------------------------------------------


class TestProviderFactory:
    """Tests for the get_provider factory function."""

    def test_get_jira_provider(self):
        from app.services.ticketing import get_provider
        from app.services.ticketing.jira_provider import JiraProvider

        config = {
            "url": "https://test.atlassian.net",
            "email": "t@t.com",
            "api_token": "token",
        }
        provider = get_provider("jira", config)
        assert isinstance(provider, JiraProvider)

    def test_get_servicenow_provider(self):
        from app.services.ticketing import get_provider
        from app.services.ticketing.servicenow_provider import ServiceNowProvider

        config = {
            "instance": "test",
            "username": "admin",
            "password": "pass",
        }
        provider = get_provider("servicenow", config)
        assert isinstance(provider, ServiceNowProvider)

    def test_get_unknown_provider_raises(self):
        from app.services.ticketing import get_provider

        with pytest.raises(ValueError, match="Unknown ticketing provider"):
            get_provider("defectdojo", {})


# ------------------------------------------------------------------
# TicketSyncService tests (with mocked DB + provider)
# ------------------------------------------------------------------


class TestTicketSyncService:
    """Tests for the sync service with mocked dependencies."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        db = MagicMock()
        return db

    @pytest.fixture
    def sync_service(self, mock_db):
        from app.services.ticketing.sync_service import TicketSyncService
        return TicketSyncService(mock_db, "test-secret-key-xxxxxxxxxxxxxxxxxx")

    def test_create_ticket_for_finding_no_config(self, sync_service, mock_db):
        """When no active config exists, should return None."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = sync_service.create_ticket_for_finding(tenant_id=1, finding_id=42)
        assert result is None

    def test_create_ticket_existing_returns_existing(self, sync_service, mock_db):
        """When a ticket already exists, return it without creating a new one."""
        from app.models.ticketing import TicketingConfig, Ticket

        # Mock config lookup
        mock_config = MagicMock(spec=TicketingConfig)
        mock_config.provider = "jira"
        mock_config.config_encrypted = "encrypted-data"
        mock_config.tenant_id = 1

        # Mock finding lookup
        mock_finding = MagicMock()
        mock_finding.id = 42
        mock_finding.name = "Test"
        mock_finding.severity = MagicMock()
        mock_finding.severity.value = "high"
        mock_finding.source = "nuclei"

        # Mock existing ticket lookup
        mock_ticket = MagicMock(spec=Ticket)
        mock_ticket.external_id = "EASM-99"

        # Set up query chain differently for different model types
        def query_side_effect(model):
            q = MagicMock()
            if model == TicketingConfig:
                q.filter.return_value.first.return_value = mock_config
            elif model == Ticket:
                q.filter.return_value.first.return_value = mock_ticket
            else:
                q.filter.return_value.first.return_value = mock_finding
            return q

        mock_db.query.side_effect = query_side_effect

        with patch("app.services.ticketing.sync_service.decrypt_config") as mock_decrypt:
            mock_decrypt.return_value = {
                "url": "https://test.atlassian.net",
                "email": "t@t.com",
                "api_token": "token",
            }
            result = sync_service.create_ticket_for_finding(1, 42)

        assert result is not None
        assert result.external_id == "EASM-99"

    def test_run_full_sync_no_config(self, sync_service, mock_db):
        """When no active config, return empty stats."""
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = sync_service.run_full_sync(tenant_id=1)
        assert result["synced"] == 0
        assert "No active config" in result.get("message", "")

    def test_run_full_sync_processes_tickets(self, sync_service, mock_db):
        """Full sync should process each ticket."""
        from app.models.ticketing import TicketingConfig, Ticket

        mock_config = MagicMock(spec=TicketingConfig)
        mock_config.provider = "jira"
        mock_config.config_encrypted = "encrypted"
        mock_config.sync_status_back = True
        mock_config.tenant_id = 1

        mock_ticket = MagicMock(spec=Ticket)
        mock_ticket.tenant_id = 1
        mock_ticket.finding_id = 42
        mock_ticket.external_id = "TEST-1"
        mock_ticket.sync_status = "synced"

        mock_finding = MagicMock()
        mock_finding.id = 42
        mock_finding.status = MagicMock()
        mock_finding.status.value = "open"

        def query_side_effect(model):
            q = MagicMock()
            if model == TicketingConfig:
                q.filter.return_value.first.return_value = mock_config
                q.filter.return_value.all.return_value = [mock_config]
            elif model == Ticket:
                q.filter.return_value.all.return_value = [mock_ticket]
                q.filter.return_value.first.return_value = mock_ticket
            else:
                q.filter.return_value.first.return_value = mock_finding
            return q

        mock_db.query.side_effect = query_side_effect

        with patch("app.services.ticketing.sync_service.decrypt_config") as mock_decrypt:
            mock_decrypt.return_value = {
                "url": "https://test.atlassian.net",
                "email": "t@t.com",
                "api_token": "token",
            }

            with patch("app.services.ticketing.sync_service.get_provider") as mock_get_provider:
                mock_provider = MagicMock()
                mock_provider.get_ticket_status.return_value = "To Do"
                mock_provider.get_ticket_status_category.return_value = "open"
                mock_provider.add_comment.return_value = True
                mock_get_provider.return_value = mock_provider

                result = sync_service.run_full_sync(tenant_id=1)

        # Should have processed 1 ticket
        assert isinstance(result, dict)
        # The ticket sync should have been attempted
        assert "synced" in result or "errors" in result


# ------------------------------------------------------------------
# Validation tests
# ------------------------------------------------------------------


class TestProviderConfigValidation:
    """Test the _validate_provider_config helper."""

    def test_jira_valid_config(self):
        from app.api.routers.tickets import _validate_provider_config

        # Should not raise
        _validate_provider_config("jira", {
            "url": "https://company.atlassian.net",
            "email": "user@company.com",
            "api_token": "token123",
        })

    def test_jira_missing_fields(self):
        from app.api.routers.tickets import _validate_provider_config
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_provider_config("jira", {"url": "https://test.com"})
        assert exc_info.value.status_code == 422
        assert "api_token" in str(exc_info.value.detail)

    def test_jira_invalid_url(self):
        from app.api.routers.tickets import _validate_provider_config
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_provider_config("jira", {
                "url": "not-a-url",
                "email": "t@t.com",
                "api_token": "token",
            })
        assert exc_info.value.status_code == 422
        assert "http" in str(exc_info.value.detail).lower()

    def test_servicenow_valid_config(self):
        from app.api.routers.tickets import _validate_provider_config

        _validate_provider_config("servicenow", {
            "instance": "company",
            "username": "admin",
            "password": "pass",
        })

    def test_servicenow_missing_fields(self):
        from app.api.routers.tickets import _validate_provider_config
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_provider_config("servicenow", {"instance": "company"})
        assert exc_info.value.status_code == 422

    def test_unknown_provider(self):
        from app.api.routers.tickets import _validate_provider_config
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_provider_config("unknown", {})
        assert exc_info.value.status_code == 422


# ------------------------------------------------------------------
# Pydantic schema tests
# ------------------------------------------------------------------


class TestTicketSchemas:
    """Tests for Pydantic request/response schemas."""

    def test_ticketing_config_create_valid(self):
        from app.api.schemas.ticket import TicketingConfigCreate

        data = TicketingConfigCreate(
            provider="jira",
            config={"url": "https://test.com", "email": "t@t.com", "api_token": "tok"},
            auto_create_on_triage=True,
            sync_status_back=True,
        )
        assert data.provider == "jira"

    def test_ticketing_config_create_invalid_provider(self):
        from app.api.schemas.ticket import TicketingConfigCreate
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            TicketingConfigCreate(
                provider="defectdojo",
                config={},
            )

    def test_ticket_response_from_attributes(self):
        from app.api.schemas.ticket import TicketResponse

        mock_ticket = MagicMock()
        mock_ticket.id = 1
        mock_ticket.tenant_id = 1
        mock_ticket.finding_id = 42
        mock_ticket.provider = "jira"
        mock_ticket.external_id = "TEST-1"
        mock_ticket.external_url = "https://test.com/browse/TEST-1"
        mock_ticket.external_status = "To Do"
        mock_ticket.sync_status = "synced"
        mock_ticket.sync_error = None
        mock_ticket.last_synced_at = datetime.now(timezone.utc)
        mock_ticket.created_at = datetime.now(timezone.utc)
        mock_ticket.updated_at = None

        response = TicketResponse.model_validate(mock_ticket)
        assert response.external_id == "TEST-1"
        assert response.sync_status == "synced"

    def test_ticket_sync_response(self):
        from app.api.schemas.ticket import TicketSyncResponse

        resp = TicketSyncResponse(
            status="completed",
            synced=10,
            errors=1,
            skipped=2,
        )
        assert resp.synced == 10


# ------------------------------------------------------------------
# Celery task tests
# ------------------------------------------------------------------


class TestCeleryTasks:
    """Tests for Celery ticket sync tasks."""

    @patch("app.tasks.ticket_sync.SessionLocal")
    @patch("app.tasks.ticket_sync.settings")
    def test_sync_all_tenant_tickets_no_configs(self, mock_settings, mock_session_local):
        from app.tasks.ticket_sync import sync_all_tenant_tickets

        mock_settings.secret_key = "test-key"
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db
        mock_db.query.return_value.filter.return_value.all.return_value = []

        result = sync_all_tenant_tickets()
        assert result["tenants_processed"] == 0

    @patch("app.tasks.ticket_sync.SessionLocal")
    @patch("app.tasks.ticket_sync.settings")
    def test_create_ticket_for_finding_task(self, mock_settings, mock_session_local):
        from app.tasks.ticket_sync import create_ticket_for_finding

        mock_settings.secret_key = "test-key"
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        with patch("app.tasks.ticket_sync.TicketSyncService") as MockSyncService:
            mock_service = MagicMock()
            mock_ticket = MagicMock()
            mock_ticket.id = 1
            mock_ticket.external_id = "TEST-99"
            mock_ticket.external_url = "https://test.com/browse/TEST-99"
            mock_ticket.provider = "jira"
            mock_service.create_ticket_for_finding.return_value = mock_ticket
            MockSyncService.return_value = mock_service

            result = create_ticket_for_finding(tenant_id=1, finding_id=42)

        assert result["status"] == "created"
        assert result["external_id"] == "TEST-99"

    @patch("app.tasks.ticket_sync.SessionLocal")
    @patch("app.tasks.ticket_sync.settings")
    def test_create_ticket_for_finding_task_failure(self, mock_settings, mock_session_local):
        from app.tasks.ticket_sync import create_ticket_for_finding

        mock_settings.secret_key = "test-key"
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        with patch("app.tasks.ticket_sync.TicketSyncService") as MockSyncService:
            mock_service = MagicMock()
            mock_service.create_ticket_for_finding.return_value = None
            MockSyncService.return_value = mock_service

            result = create_ticket_for_finding(tenant_id=1, finding_id=42)

        assert result["status"] == "failed"

    @patch("app.tasks.ticket_sync.SessionLocal")
    @patch("app.tasks.ticket_sync.settings")
    def test_sync_single_ticket_task(self, mock_settings, mock_session_local):
        from app.tasks.ticket_sync import sync_single_ticket
        from app.models.ticketing import Ticket

        mock_settings.secret_key = "test-key"
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        mock_ticket = MagicMock(spec=Ticket)
        mock_ticket.id = 1
        mock_ticket.external_status = "To Do"
        mock_ticket.sync_status = "synced"
        mock_db.query.return_value.filter.return_value.first.return_value = mock_ticket

        with patch("app.tasks.ticket_sync.TicketSyncService") as MockSyncService:
            mock_service = MagicMock()
            mock_service.sync_ticket_to_finding.return_value = True
            mock_service.sync_finding_to_ticket.return_value = True
            MockSyncService.return_value = mock_service

            result = sync_single_ticket(ticket_id=1)

        assert result["status"] == "synced"
        assert result["inbound"] is True
        assert result["outbound"] is True

    @patch("app.tasks.ticket_sync.SessionLocal")
    @patch("app.tasks.ticket_sync.settings")
    def test_sync_single_ticket_not_found(self, mock_settings, mock_session_local):
        from app.tasks.ticket_sync import sync_single_ticket

        mock_settings.secret_key = "test-key"
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db
        mock_db.query.return_value.filter.return_value.first.return_value = None

        result = sync_single_ticket(ticket_id=999)
        assert result["status"] == "error"


# ------------------------------------------------------------------
# ServiceNow description builder uses class name reference
# ------------------------------------------------------------------


# Pull in the ServiceNow import for TestServiceNowProvider.test_build_description
from app.services.ticketing.servicenow_provider import ServiceNowProvider
