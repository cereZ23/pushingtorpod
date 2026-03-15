"""
ServiceNow integration provider.

Implements the TicketingProvider interface for ServiceNow using the Table API.

Config required:
    instance: str   - ServiceNow instance name (e.g., "company" for company.service-now.com)
    username: str   - ServiceNow user
    password: str   - ServiceNow password
    table: str      - Target table (default: "incident")

Security:
    - Credentials are passed in at initialization from encrypted storage.
    - NEVER log or serialize the password.
"""

import logging
import httpx
from typing import Optional

from app.services.ticketing import TicketingProvider, TicketData, TicketResult
from app.utils.validators import validate_endpoint_url_ssrf

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_RETRY_BACKOFF_SECONDS = [1, 3, 9]


class ServiceNowProvider(TicketingProvider):
    """ServiceNow Table API ticketing provider."""

    SEVERITY_TO_IMPACT = {
        "critical": "1",  # High
        "high": "2",      # Medium
        "medium": "2",    # Medium
        "low": "3",       # Low
        "info": "3",      # Low
    }

    SEVERITY_TO_URGENCY = {
        "critical": "1",  # High
        "high": "2",      # Medium
        "medium": "2",    # Medium
        "low": "3",       # Low
        "info": "3",      # Low
    }

    # ServiceNow incident state values
    SN_STATE_NEW = "1"
    SN_STATE_IN_PROGRESS = "2"
    SN_STATE_ON_HOLD = "3"
    SN_STATE_RESOLVED = "6"
    SN_STATE_CLOSED = "7"

    # Map ServiceNow state numbers to normalized EASM status
    SN_STATE_TO_EASM = {
        "1": "open",          # New
        "2": "in_progress",   # In Progress
        "3": "in_progress",   # On Hold
        "6": "resolved",      # Resolved
        "7": "closed",        # Closed
    }

    def __init__(self, config: dict):
        instance = config["instance"]
        base_url = f"https://{instance}.service-now.com"
        # SSRF protection: validate the constructed ServiceNow URL
        validate_endpoint_url_ssrf(base_url, require_https=True)
        self.base_url = base_url
        self.table = config.get("table", "incident")
        self._username = config["username"]
        self._password = config["password"]
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        """Lazy-init an httpx Client with auth and base_url."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                base_url=f"{self.base_url}/api/now",
                auth=(self._username, self._password),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    def _request_with_retry(
        self, method: str, path: str, **kwargs
    ) -> httpx.Response:
        """
        Execute an HTTP request with exponential-backoff retries
        on transient errors (5xx, timeouts, connection errors).
        """
        import time

        client = self._get_client()
        last_exc: Optional[Exception] = None

        for attempt in range(_MAX_RETRIES):
            try:
                response = client.request(method, path, **kwargs)
                if response.status_code >= 500:
                    logger.warning(
                        "ServiceNow returned %d on attempt %d for %s %s",
                        response.status_code,
                        attempt + 1,
                        method,
                        path,
                    )
                    if attempt < _MAX_RETRIES - 1:
                        time.sleep(_RETRY_BACKOFF_SECONDS[attempt])
                        continue
                return response
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                logger.warning(
                    "ServiceNow request failed on attempt %d: %s",
                    attempt + 1,
                    exc,
                )
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF_SECONDS[attempt])

        raise ConnectionError(
            f"ServiceNow request failed after {_MAX_RETRIES} attempts: {last_exc}"
        )

    @staticmethod
    def _build_description(data: TicketData) -> str:
        """Build a plain-text description for a ServiceNow incident."""
        lines = [
            f"EASM Finding: {data.title}",
            f"Severity: {data.severity.upper()}",
            "",
            data.description or "",
            "",
        ]

        if data.custom_fields:
            lines.append("--- Additional Details ---")
            for key, value in data.custom_fields.items():
                lines.append(f"{key}: {value}")
            lines.append("")

        lines.append(
            f"[Auto-created by EASM Platform - "
            f"finding_id={data.finding_id}, tenant_id={data.tenant_id}]"
        )

        return "\n".join(lines)

    def _sys_id_from_number(self, number: str) -> str:
        """
        Resolve a ServiceNow record number (e.g., INC0012345) to its sys_id.

        The Table API requires sys_id for PATCH/GET operations on specific records,
        but many callers use the display number instead.
        """
        response = self._request_with_retry(
            "GET",
            f"/table/{self.table}",
            params={
                "sysparm_query": f"number={number}",
                "sysparm_fields": "sys_id",
                "sysparm_limit": "1",
            },
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"ServiceNow lookup for {number} failed ({response.status_code})"
            )

        results = response.json().get("result", [])
        if not results:
            raise RuntimeError(f"ServiceNow record not found: {number}")

        return results[0]["sys_id"]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_ticket(self, data: TicketData) -> TicketResult:
        """
        Create a ServiceNow incident.

        POST /api/now/table/{table}
        """
        payload = {
            "short_description": data.title[:160],  # SN limit
            "description": self._build_description(data),
            "impact": self.SEVERITY_TO_IMPACT.get(data.severity, "2"),
            "urgency": self.SEVERITY_TO_URGENCY.get(data.severity, "2"),
            "category": "Security",
            "subcategory": "Vulnerability",
        }

        if data.assignee:
            payload["assigned_to"] = data.assignee

        response = self._request_with_retry(
            "POST", f"/table/{self.table}", json=payload
        )

        if response.status_code not in (200, 201):
            error_detail = response.text[:500]
            logger.error(
                "Failed to create ServiceNow incident: %d - %s",
                response.status_code,
                error_detail,
            )
            raise RuntimeError(
                f"ServiceNow incident creation failed ({response.status_code}): "
                f"{error_detail}"
            )

        result_data = response.json().get("result", {})
        number = result_data.get("number", "")
        sys_id = result_data.get("sys_id", "")
        incident_url = f"{self.base_url}/nav_to.do?uri={self.table}.do?sys_id={sys_id}"

        logger.info(
            "Created ServiceNow incident %s for finding %d",
            number,
            data.finding_id,
        )

        return TicketResult(
            external_id=number,
            external_url=incident_url,
            external_status="New",
            raw_response=result_data,
        )

    def update_ticket(self, external_id: str, data: dict) -> TicketResult:
        """
        Update a ServiceNow incident's fields.

        PATCH /api/now/table/{table}/{sys_id}
        """
        sys_id = self._sys_id_from_number(external_id)

        response = self._request_with_retry(
            "PATCH", f"/table/{self.table}/{sys_id}", json=data
        )

        if response.status_code not in (200, 204):
            error_detail = response.text[:500]
            logger.error(
                "Failed to update ServiceNow incident %s: %d - %s",
                external_id,
                response.status_code,
                error_detail,
            )
            raise RuntimeError(
                f"ServiceNow incident update failed ({response.status_code}): "
                f"{error_detail}"
            )

        result_data = response.json().get("result", {})
        current_state = result_data.get("state", "")
        state_label = self._state_number_to_label(current_state)

        logger.info("Updated ServiceNow incident %s", external_id)

        return TicketResult(
            external_id=external_id,
            external_url=f"{self.base_url}/nav_to.do?uri={self.table}.do?sys_id={sys_id}",
            external_status=state_label,
            raw_response=result_data,
        )

    def get_ticket_status(self, external_id: str) -> str:
        """
        Get the current status of a ServiceNow incident.

        GET /api/now/table/{table}?number={external_id}&sysparm_fields=state
        """
        response = self._request_with_retry(
            "GET",
            f"/table/{self.table}",
            params={
                "sysparm_query": f"number={external_id}",
                "sysparm_fields": "state,number",
                "sysparm_limit": "1",
            },
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"ServiceNow status fetch failed ({response.status_code})"
            )

        results = response.json().get("result", [])
        if not results:
            raise RuntimeError(f"ServiceNow record not found: {external_id}")

        state = results[0].get("state", "1")
        return self._state_number_to_label(state)

    def get_normalized_status(self, external_id: str) -> str:
        """
        Get the normalized EASM status for a ServiceNow incident.

        Returns one of: open, in_progress, resolved, closed
        """
        response = self._request_with_retry(
            "GET",
            f"/table/{self.table}",
            params={
                "sysparm_query": f"number={external_id}",
                "sysparm_fields": "state",
                "sysparm_limit": "1",
            },
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"ServiceNow status fetch failed ({response.status_code})"
            )

        results = response.json().get("result", [])
        if not results:
            raise RuntimeError(f"ServiceNow record not found: {external_id}")

        state = results[0].get("state", "1")
        return self.SN_STATE_TO_EASM.get(str(state), "open")

    def add_comment(self, external_id: str, comment: str) -> bool:
        """
        Add a work note to a ServiceNow incident.

        PATCH /api/now/table/{table}/{sys_id}
        Using the 'work_notes' field for internal comments.
        """
        try:
            sys_id = self._sys_id_from_number(external_id)
        except RuntimeError:
            logger.error("Cannot add comment - record not found: %s", external_id)
            return False

        response = self._request_with_retry(
            "PATCH",
            f"/table/{self.table}/{sys_id}",
            json={"work_notes": comment},
        )

        if response.status_code not in (200, 204):
            logger.error(
                "Failed to add comment to ServiceNow incident %s: %d",
                external_id,
                response.status_code,
            )
            return False

        logger.info("Added comment to ServiceNow incident %s", external_id)
        return True

    def close_ticket(self, external_id: str, resolution: str = "Fixed") -> bool:
        """
        Resolve and close a ServiceNow incident.

        Sets state to Resolved (6) with close_code and close_notes.
        """
        try:
            sys_id = self._sys_id_from_number(external_id)
        except RuntimeError:
            logger.error("Cannot close - record not found: %s", external_id)
            return False

        payload = {
            "state": self.SN_STATE_RESOLVED,
            "close_code": "Solved (Permanently)",
            "close_notes": f"Resolved via EASM Platform: {resolution}",
        }

        response = self._request_with_retry(
            "PATCH",
            f"/table/{self.table}/{sys_id}",
            json=payload,
        )

        if response.status_code not in (200, 204):
            logger.error(
                "Failed to close ServiceNow incident %s: %d - %s",
                external_id,
                response.status_code,
                response.text[:500],
            )
            return False

        logger.info(
            "Closed ServiceNow incident %s with resolution '%s'",
            external_id,
            resolution,
        )
        return True

    def test_connection(self) -> bool:
        """
        Test the ServiceNow connection by fetching the current user's profile.

        GET /api/now/table/sys_user?sysparm_query=user_name={username}&sysparm_limit=1
        """
        try:
            response = self._request_with_retry(
                "GET",
                "/table/sys_user",
                params={
                    "sysparm_query": f"user_name={self._username}",
                    "sysparm_fields": "user_name,name,email",
                    "sysparm_limit": "1",
                },
            )

            if response.status_code == 200:
                results = response.json().get("result", [])
                if results:
                    display_name = results[0].get("name", self._username)
                    logger.info(
                        "ServiceNow connection OK - authenticated as %s",
                        display_name,
                    )
                    return True
                logger.warning("ServiceNow connection OK but user profile not found")
                return True  # Connection works even if user lookup returns empty
            logger.error(
                "ServiceNow connection test failed: %d", response.status_code
            )
            return False
        except Exception as exc:
            logger.error("ServiceNow connection test error: %s", exc)
            return False

    @staticmethod
    def _state_number_to_label(state: str) -> str:
        """Convert a ServiceNow state number to a human-readable label."""
        labels = {
            "1": "New",
            "2": "In Progress",
            "3": "On Hold",
            "6": "Resolved",
            "7": "Closed",
        }
        return labels.get(str(state), f"Unknown ({state})")

    def __del__(self):
        """Close the HTTP client on cleanup."""
        if self._client and not self._client.is_closed:
            try:
                self._client.close()
            except Exception:
                logger.debug("Failed to close ServiceNow HTTP client during cleanup")
