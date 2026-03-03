"""
Jira Cloud / Server integration provider.

Implements the TicketingProvider interface for Jira using the REST API v3
(Atlassian Document Format for rich-text descriptions).

Config required:
    url: str        - Jira instance URL (e.g., https://company.atlassian.net)
    email: str      - Jira user email
    api_token: str  - API token (Cloud) or password (Server)
    project_key: str - Target project (e.g., "EASM")
    issue_type: str  - Default issue type (e.g., "Bug" or "Task")

Security:
    - Credentials are passed in at initialization from encrypted storage.
    - NEVER log or serialize the api_token.
"""

import logging
import httpx
from typing import Optional

from app.services.ticketing import TicketingProvider, TicketData, TicketResult

logger = logging.getLogger(__name__)

# Max retries for transient failures
_MAX_RETRIES = 3
_RETRY_BACKOFF_SECONDS = [1, 3, 9]


class JiraProvider(TicketingProvider):
    """Jira Cloud/Server ticketing provider."""

    SEVERITY_TO_PRIORITY = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }

    # Mapping from Jira status categories back to a normalized status string
    JIRA_STATUS_CATEGORY_MAP = {
        "new": "open",
        "indeterminate": "in_progress",
        "done": "closed",
    }

    def __init__(self, config: dict):
        self.url = config["url"].rstrip("/")
        self.email = config["email"]
        self.api_token = config["api_token"]
        self.project_key = config.get("project_key", "EASM")
        self.issue_type = config.get("issue_type", "Bug")
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        """Lazy-init an httpx Client with auth and base_url."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                base_url=f"{self.url}/rest/api/3",
                auth=(self.email, self.api_token),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
                        "Jira returned %d on attempt %d for %s %s",
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
                    "Jira request failed on attempt %d: %s", attempt + 1, exc
                )
                if attempt < _MAX_RETRIES - 1:
                    time.sleep(_RETRY_BACKOFF_SECONDS[attempt])

        raise ConnectionError(
            f"Jira request failed after {_MAX_RETRIES} attempts: {last_exc}"
        )

    @staticmethod
    def _build_adf_description(data: TicketData) -> dict:
        """
        Build an Atlassian Document Format (ADF) body for the ticket
        description including severity, affected assets, and evidence.
        """
        paragraphs: list[dict] = []

        def _text_node(text: str, bold: bool = False) -> dict:
            node: dict = {"type": "text", "text": text}
            if bold:
                node["marks"] = [{"type": "strong"}]
            return node

        def _paragraph(*inline_nodes: dict) -> dict:
            return {"type": "paragraph", "content": list(inline_nodes)}

        # Header line
        paragraphs.append(
            _paragraph(
                _text_node("EASM Finding: ", bold=True),
                _text_node(data.title),
            )
        )

        # Severity
        paragraphs.append(
            _paragraph(
                _text_node("Severity: ", bold=True),
                _text_node(data.severity.upper()),
            )
        )

        # Full description
        if data.description:
            paragraphs.append(_paragraph(_text_node(data.description)))

        # Custom fields info
        if data.custom_fields:
            for key, value in data.custom_fields.items():
                paragraphs.append(
                    _paragraph(
                        _text_node(f"{key}: ", bold=True),
                        _text_node(str(value)),
                    )
                )

        # Provenance
        paragraphs.append(
            _paragraph(
                _text_node(
                    f"Created automatically by EASM Platform "
                    f"(finding_id={data.finding_id}, tenant_id={data.tenant_id})"
                )
            )
        )

        return {
            "type": "doc",
            "version": 1,
            "content": paragraphs,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_ticket(self, data: TicketData) -> TicketResult:
        """
        Create a Jira issue.

        POST /rest/api/3/issue
        """
        priority_name = self.SEVERITY_TO_PRIORITY.get(data.severity, "Medium")
        labels = list(set(["easm", data.severity] + (data.labels or [])))

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": data.title[:255],  # Jira summary max length
                "description": self._build_adf_description(data),
                "issuetype": {"name": self.issue_type},
                "priority": {"name": priority_name},
                "labels": labels,
            }
        }

        if data.assignee:
            payload["fields"]["assignee"] = {"accountId": data.assignee}

        response = self._request_with_retry("POST", "/issue", json=payload)

        if response.status_code not in (200, 201):
            error_detail = response.text[:500]
            logger.error(
                "Failed to create Jira issue: %d - %s",
                response.status_code,
                error_detail,
            )
            raise RuntimeError(
                f"Jira issue creation failed ({response.status_code}): {error_detail}"
            )

        result_data = response.json()
        issue_key = result_data["key"]
        issue_url = f"{self.url}/browse/{issue_key}"

        logger.info("Created Jira issue %s for finding %d", issue_key, data.finding_id)

        return TicketResult(
            external_id=issue_key,
            external_url=issue_url,
            external_status="To Do",
            raw_response=result_data,
        )

    def update_ticket(self, external_id: str, data: dict) -> TicketResult:
        """
        Update a Jira issue's fields.

        PUT /rest/api/3/issue/{issueIdOrKey}
        """
        payload = {"fields": data}
        response = self._request_with_retry(
            "PUT", f"/issue/{external_id}", json=payload
        )

        if response.status_code not in (200, 204):
            error_detail = response.text[:500]
            logger.error(
                "Failed to update Jira issue %s: %d - %s",
                external_id,
                response.status_code,
                error_detail,
            )
            raise RuntimeError(
                f"Jira issue update failed ({response.status_code}): {error_detail}"
            )

        # Fetch current state after update
        current_status = self.get_ticket_status(external_id)

        logger.info("Updated Jira issue %s", external_id)

        return TicketResult(
            external_id=external_id,
            external_url=f"{self.url}/browse/{external_id}",
            external_status=current_status,
        )

    def get_ticket_status(self, external_id: str) -> str:
        """
        Get the current status of a Jira issue.

        GET /rest/api/3/issue/{issueIdOrKey}?fields=status
        """
        response = self._request_with_retry(
            "GET", f"/issue/{external_id}", params={"fields": "status"}
        )

        if response.status_code != 200:
            logger.error(
                "Failed to get Jira issue %s status: %d",
                external_id,
                response.status_code,
            )
            raise RuntimeError(
                f"Jira status fetch failed ({response.status_code})"
            )

        data = response.json()
        return data["fields"]["status"]["name"]

    def get_ticket_status_category(self, external_id: str) -> str:
        """
        Get the normalized status category key for a Jira issue.

        Jira groups statuses into categories: 'new', 'indeterminate', 'done'.
        This is more reliable for mapping than the raw status name.
        """
        response = self._request_with_retry(
            "GET", f"/issue/{external_id}", params={"fields": "status"}
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"Jira status fetch failed ({response.status_code})"
            )

        data = response.json()
        category_key = (
            data["fields"]["status"]
            .get("statusCategory", {})
            .get("key", "indeterminate")
        )
        return self.JIRA_STATUS_CATEGORY_MAP.get(category_key, "in_progress")

    def add_comment(self, external_id: str, comment: str) -> bool:
        """
        Add a comment to a Jira issue.

        POST /rest/api/3/issue/{issueIdOrKey}/comment
        """
        adf_body = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": comment}],
                }
            ],
        }

        response = self._request_with_retry(
            "POST",
            f"/issue/{external_id}/comment",
            json={"body": adf_body},
        )

        if response.status_code not in (200, 201):
            logger.error(
                "Failed to add comment to Jira issue %s: %d",
                external_id,
                response.status_code,
            )
            return False

        logger.info("Added comment to Jira issue %s", external_id)
        return True

    def close_ticket(self, external_id: str, resolution: str = "Fixed") -> bool:
        """
        Transition a Jira issue to Done/Closed.

        1. GET /rest/api/3/issue/{id}/transitions - find the close transition
        2. POST /rest/api/3/issue/{id}/transitions - execute transition
        """
        # Step 1: Discover available transitions
        response = self._request_with_retry(
            "GET", f"/issue/{external_id}/transitions"
        )

        if response.status_code != 200:
            logger.error(
                "Failed to get transitions for Jira issue %s: %d",
                external_id,
                response.status_code,
            )
            return False

        transitions = response.json().get("transitions", [])

        # Find a transition whose target status category is "done"
        close_transition_id = None
        done_keywords = {"done", "closed", "resolved", "complete", "fixed"}
        for transition in transitions:
            name_lower = transition.get("name", "").lower()
            to_category = (
                transition.get("to", {})
                .get("statusCategory", {})
                .get("key", "")
            )
            if to_category == "done" or name_lower in done_keywords:
                close_transition_id = transition["id"]
                break

        if close_transition_id is None:
            logger.warning(
                "No close/done transition found for Jira issue %s. "
                "Available transitions: %s",
                external_id,
                [t["name"] for t in transitions],
            )
            return False

        # Step 2: Execute the transition
        transition_payload: dict = {
            "transition": {"id": close_transition_id},
        }

        # Try to set resolution if available
        if resolution:
            transition_payload["fields"] = {
                "resolution": {"name": resolution}
            }

        response = self._request_with_retry(
            "POST",
            f"/issue/{external_id}/transitions",
            json=transition_payload,
        )

        if response.status_code not in (200, 204):
            # Retry without resolution field in case it is not supported
            transition_payload.pop("fields", None)
            response = self._request_with_retry(
                "POST",
                f"/issue/{external_id}/transitions",
                json=transition_payload,
            )

            if response.status_code not in (200, 204):
                logger.error(
                    "Failed to close Jira issue %s: %d - %s",
                    external_id,
                    response.status_code,
                    response.text[:500],
                )
                return False

        logger.info("Closed Jira issue %s with resolution '%s'", external_id, resolution)
        return True

    def test_connection(self) -> bool:
        """
        Test the Jira connection by calling GET /rest/api/3/myself.
        """
        try:
            response = self._request_with_retry("GET", "/myself")
            if response.status_code == 200:
                user_info = response.json()
                logger.info(
                    "Jira connection OK - authenticated as %s",
                    user_info.get("displayName", user_info.get("emailAddress", "unknown")),
                )
                return True
            logger.error(
                "Jira connection test failed: %d", response.status_code
            )
            return False
        except Exception as exc:
            logger.error("Jira connection test error: %s", exc)
            return False

    def __del__(self):
        """Close the HTTP client on cleanup."""
        if self._client and not self._client.is_closed:
            try:
                self._client.close()
            except Exception:
                pass
