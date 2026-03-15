"""
Ticketing integration service.

Supports Jira Cloud, Jira Server, and ServiceNow.
Provides a unified interface for creating, updating, and syncing tickets
with external issue tracking systems.

Usage:
    from app.services.ticketing import get_provider, TicketData

    provider = get_provider('jira', config_dict)
    result = provider.create_ticket(TicketData(
        title="Critical CVE on api.example.com",
        description="...",
        severity="critical",
        finding_id=42,
        tenant_id=1,
    ))
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TicketData:
    """Data structure for creating/updating tickets."""

    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    finding_id: int
    tenant_id: int
    assignee: Optional[str] = None
    labels: list[str] = field(default_factory=list)
    custom_fields: dict = field(default_factory=dict)


@dataclass
class TicketResult:
    """Result from ticket operations."""

    external_id: str  # e.g., "EASM-123" or "INC0012345"
    external_url: str
    external_status: str
    raw_response: dict = field(default_factory=dict)


class TicketingProvider(ABC):
    """Abstract base class for ticketing integrations."""

    @abstractmethod
    def create_ticket(self, data: TicketData) -> TicketResult:
        """Create a new ticket in the external system."""
        ...

    @abstractmethod
    def update_ticket(self, external_id: str, data: dict) -> TicketResult:
        """Update an existing ticket's fields."""
        ...

    @abstractmethod
    def get_ticket_status(self, external_id: str) -> str:
        """Retrieve the current status of a ticket."""
        ...

    @abstractmethod
    def add_comment(self, external_id: str, comment: str) -> bool:
        """Add a comment to an existing ticket."""
        ...

    @abstractmethod
    def close_ticket(self, external_id: str, resolution: str = "Fixed") -> bool:
        """Transition a ticket to Done/Closed/Resolved state."""
        ...

    @abstractmethod
    def test_connection(self) -> bool:
        """Test connectivity and authentication to the external system."""
        ...


def get_provider(provider_type: str, config: dict) -> TicketingProvider:
    """
    Factory function to instantiate the correct ticketing provider.

    Args:
        provider_type: One of 'jira' or 'servicenow'.
        config: Provider-specific configuration dictionary.

    Returns:
        An initialized TicketingProvider instance.

    Raises:
        ValueError: If provider_type is not recognized.
    """
    if provider_type == "jira":
        from .jira_provider import JiraProvider

        return JiraProvider(config)
    elif provider_type == "servicenow":
        from .servicenow_provider import ServiceNowProvider

        return ServiceNowProvider(config)
    raise ValueError(f"Unknown ticketing provider: '{provider_type}'. Supported providers: jira, servicenow")


__all__ = [
    "TicketData",
    "TicketResult",
    "TicketingProvider",
    "get_provider",
]
