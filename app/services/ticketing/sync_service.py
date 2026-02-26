"""
Bi-directional ticket synchronization service.

Handles the two-way sync between EASM findings and external tickets:

Outbound (EASM -> External):
    - Finding status changes push updates to the linked ticket.
    - New findings can auto-create tickets if auto_create_on_triage is enabled.

Inbound (External -> EASM):
    - Ticket status changes pull back into EASM finding status.
    - Closed tickets mark the finding as 'fixed'.

Status Mapping (Default):
    EASM open         -> Jira "To Do"      / SN "New" (1)
    EASM in_progress  -> Jira "In Progress" / SN "In Progress" (2)
    EASM suppressed   -> (add comment, no status change)
    EASM fixed        -> Jira "Done"        / SN "Resolved" (6)
    (reverse direction)
    Jira "Done"/SN "Resolved"  -> EASM fixed
    Jira "To Do"/SN "New"      -> EASM open
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models.database import Finding, FindingStatus
from app.models.ticketing import Ticket, TicketingConfig
from app.services.ticketing import get_provider, TicketData, TicketingProvider
from app.services.ticketing.crypto import decrypt_config

logger = logging.getLogger(__name__)

# Mapping from normalized external status to FindingStatus
EXTERNAL_STATUS_TO_FINDING = {
    "open": FindingStatus.OPEN,
    "in_progress": FindingStatus.OPEN,  # EASM has no in_progress, keep open
    "resolved": FindingStatus.FIXED,
    "closed": FindingStatus.FIXED,
}

# Mapping from FindingStatus to a comment for outbound sync
FINDING_STATUS_LABELS = {
    FindingStatus.OPEN: "open",
    FindingStatus.SUPPRESSED: "suppressed",
    FindingStatus.FIXED: "fixed",
}


class TicketSyncService:
    """
    Orchestrates bi-directional synchronization between EASM findings
    and external ticketing systems.
    """

    def __init__(self, db: Session, secret_key: str):
        self.db = db
        self.secret_key = secret_key

    # ------------------------------------------------------------------
    # Provider resolution
    # ------------------------------------------------------------------

    def _get_provider_for_tenant(self, tenant_id: int) -> Optional[tuple[TicketingProvider, TicketingConfig]]:
        """
        Load and instantiate the ticketing provider for a tenant.

        Returns:
            Tuple of (provider_instance, config_record) or None if not configured.
        """
        config_record = (
            self.db.query(TicketingConfig)
            .filter(
                TicketingConfig.tenant_id == tenant_id,
                TicketingConfig.is_active == True,  # noqa: E712
            )
            .first()
        )

        if not config_record:
            return None

        plain_config = decrypt_config(config_record.config_encrypted, self.secret_key)
        if not plain_config:
            logger.error(
                "Failed to decrypt ticketing config for tenant %d", tenant_id
            )
            return None

        try:
            provider = get_provider(config_record.provider, plain_config)
        except ValueError as exc:
            logger.error("Invalid provider for tenant %d: %s", tenant_id, exc)
            return None

        return provider, config_record

    # ------------------------------------------------------------------
    # Ticket creation
    # ------------------------------------------------------------------

    def create_ticket_for_finding(
        self, tenant_id: int, finding_id: int
    ) -> Optional[Ticket]:
        """
        Create a new external ticket for a finding and store the mapping.

        Args:
            tenant_id: Tenant owning the finding.
            finding_id: ID of the finding to create a ticket for.

        Returns:
            The created Ticket record, or None on failure.
        """
        result = self._get_provider_for_tenant(tenant_id)
        if not result:
            logger.warning(
                "No active ticketing config for tenant %d, cannot create ticket",
                tenant_id,
            )
            return None

        provider, config_record = result

        # Load finding
        finding = self.db.query(Finding).filter(Finding.id == finding_id).first()
        if not finding:
            logger.error("Finding %d not found", finding_id)
            return None

        # Check for existing ticket
        existing = (
            self.db.query(Ticket)
            .filter(
                Ticket.finding_id == finding_id,
                Ticket.tenant_id == tenant_id,
            )
            .first()
        )
        if existing:
            logger.info(
                "Ticket already exists for finding %d: %s",
                finding_id,
                existing.external_id,
            )
            return existing

        # Build ticket data
        description_parts = [
            f"Vulnerability: {finding.name}",
            f"Source: {finding.source}",
        ]
        if finding.cve_id:
            description_parts.append(f"CVE: {finding.cve_id}")
        if finding.cvss_score is not None:
            description_parts.append(f"CVSS: {finding.cvss_score}")
        if finding.template_id:
            description_parts.append(f"Template: {finding.template_id}")
        if finding.matched_at:
            description_parts.append(f"Matched at: {finding.matched_at}")

        # Include evidence summary if available
        custom_fields = {}
        if finding.evidence and isinstance(finding.evidence, dict):
            for key, value in finding.evidence.items():
                if isinstance(value, str) and len(value) < 500:
                    custom_fields[key] = value

        ticket_data = TicketData(
            title=f"[EASM] {finding.severity.value.upper()}: {finding.name}"[:255],
            description="\n".join(description_parts),
            severity=finding.severity.value,
            finding_id=finding_id,
            tenant_id=tenant_id,
            custom_fields=custom_fields,
        )

        try:
            ticket_result = provider.create_ticket(ticket_data)
        except Exception as exc:
            logger.error(
                "Failed to create ticket for finding %d: %s", finding_id, exc
            )
            return None

        # Persist the ticket record
        ticket = Ticket(
            tenant_id=tenant_id,
            finding_id=finding_id,
            provider=config_record.provider,
            external_id=ticket_result.external_id,
            external_url=ticket_result.external_url,
            external_status=ticket_result.external_status,
            sync_status="synced",
            last_synced_at=datetime.now(timezone.utc),
            external_metadata=ticket_result.raw_response or {},
        )

        self.db.add(ticket)
        self.db.commit()
        self.db.refresh(ticket)

        logger.info(
            "Created ticket %s for finding %d (tenant %d)",
            ticket.external_id,
            finding_id,
            tenant_id,
        )

        return ticket

    # ------------------------------------------------------------------
    # Outbound sync: EASM -> External
    # ------------------------------------------------------------------

    def sync_finding_to_ticket(self, ticket: Ticket) -> bool:
        """
        Push the current EASM finding status to the linked external ticket.

        When a finding is marked as fixed in EASM, close the ticket.
        When a finding is suppressed, add a comment but do not close.
        """
        result = self._get_provider_for_tenant(ticket.tenant_id)
        if not result:
            return False

        provider, _config_record = result

        finding = self.db.query(Finding).filter(Finding.id == ticket.finding_id).first()
        if not finding:
            logger.error("Finding %d not found for ticket %d", ticket.finding_id, ticket.id)
            ticket.sync_status = "error"
            ticket.sync_error = "Finding not found"
            self.db.commit()
            return False

        try:
            if finding.status == FindingStatus.FIXED:
                success = provider.close_ticket(
                    ticket.external_id, resolution="Fixed"
                )
                if success:
                    ticket.external_status = "Closed"
                    ticket.sync_status = "synced"
                else:
                    ticket.sync_status = "error"
                    ticket.sync_error = "Failed to close ticket"

            elif finding.status == FindingStatus.SUPPRESSED:
                provider.add_comment(
                    ticket.external_id,
                    "This finding has been suppressed in the EASM platform (false positive or accepted risk).",
                )
                ticket.sync_status = "synced"

            elif finding.status == FindingStatus.OPEN:
                # Re-open scenario: add comment if ticket was previously closed
                provider.add_comment(
                    ticket.external_id,
                    "This finding has been re-opened in the EASM platform.",
                )
                ticket.sync_status = "synced"

            ticket.last_synced_at = datetime.now(timezone.utc)
            ticket.sync_error = None
            self.db.commit()
            return True

        except Exception as exc:
            logger.error(
                "Outbound sync failed for ticket %s: %s",
                ticket.external_id,
                exc,
            )
            ticket.sync_status = "error"
            ticket.sync_error = str(exc)[:500]
            ticket.last_synced_at = datetime.now(timezone.utc)
            self.db.commit()
            return False

    # ------------------------------------------------------------------
    # Inbound sync: External -> EASM
    # ------------------------------------------------------------------

    def sync_ticket_to_finding(self, ticket: Ticket) -> bool:
        """
        Pull the current external ticket status and update the EASM finding.

        If the ticket is resolved/closed externally, mark the finding as fixed.
        """
        result = self._get_provider_for_tenant(ticket.tenant_id)
        if not result:
            return False

        provider, config_record = result

        # Check if inbound sync is enabled
        if not config_record.sync_status_back:
            return True  # Nothing to do, not an error

        finding = self.db.query(Finding).filter(Finding.id == ticket.finding_id).first()
        if not finding:
            logger.error("Finding %d not found for ticket %d", ticket.finding_id, ticket.id)
            ticket.sync_status = "error"
            ticket.sync_error = "Finding not found"
            self.db.commit()
            return False

        try:
            # Get normalized status from external system
            if config_record.provider == "jira":
                from app.services.ticketing.jira_provider import JiraProvider
                if isinstance(provider, JiraProvider):
                    normalized_status = provider.get_ticket_status_category(
                        ticket.external_id
                    )
                else:
                    normalized_status = "open"
            elif config_record.provider == "servicenow":
                from app.services.ticketing.servicenow_provider import ServiceNowProvider
                if isinstance(provider, ServiceNowProvider):
                    normalized_status = provider.get_normalized_status(
                        ticket.external_id
                    )
                else:
                    normalized_status = "open"
            else:
                # Fallback: get raw status
                raw_status = provider.get_ticket_status(ticket.external_id)
                normalized_status = raw_status.lower().replace(" ", "_")

            # Update ticket's external_status
            raw_display_status = provider.get_ticket_status(ticket.external_id)
            ticket.external_status = raw_display_status

            # Map to EASM finding status
            new_finding_status = EXTERNAL_STATUS_TO_FINDING.get(normalized_status)
            if new_finding_status and new_finding_status != finding.status:
                old_status = finding.status.value
                finding.status = new_finding_status
                logger.info(
                    "Inbound sync: finding %d status changed %s -> %s "
                    "(from ticket %s status '%s')",
                    finding.id,
                    old_status,
                    new_finding_status.value,
                    ticket.external_id,
                    normalized_status,
                )

            ticket.sync_status = "synced"
            ticket.sync_error = None
            ticket.last_synced_at = datetime.now(timezone.utc)
            self.db.commit()
            return True

        except Exception as exc:
            logger.error(
                "Inbound sync failed for ticket %s: %s",
                ticket.external_id,
                exc,
            )
            ticket.sync_status = "error"
            ticket.sync_error = str(exc)[:500]
            ticket.last_synced_at = datetime.now(timezone.utc)
            self.db.commit()
            return False

    # ------------------------------------------------------------------
    # Full sync
    # ------------------------------------------------------------------

    def run_full_sync(self, tenant_id: int) -> dict:
        """
        Perform a full bi-directional sync for all open tickets of a tenant.

        Returns:
            Summary dict: {synced, errors, skipped}
        """
        result = self._get_provider_for_tenant(tenant_id)
        if not result:
            return {"synced": 0, "errors": 0, "skipped": 0, "message": "No active config"}

        tickets = (
            self.db.query(Ticket)
            .filter(
                Ticket.tenant_id == tenant_id,
                Ticket.sync_status != "conflict",
            )
            .all()
        )

        stats = {"synced": 0, "errors": 0, "skipped": 0}

        for ticket in tickets:
            # Skip tickets for closed/fixed findings that are already synced
            finding = self.db.query(Finding).filter(Finding.id == ticket.finding_id).first()
            if not finding:
                stats["skipped"] += 1
                continue

            # Inbound: pull external status
            inbound_ok = self.sync_ticket_to_finding(ticket)

            # Outbound: push finding status (only if finding changed and inbound succeeded)
            if inbound_ok:
                outbound_ok = self.sync_finding_to_ticket(ticket)
                if outbound_ok:
                    stats["synced"] += 1
                else:
                    stats["errors"] += 1
            else:
                stats["errors"] += 1

        logger.info(
            "Full sync for tenant %d: synced=%d, errors=%d, skipped=%d",
            tenant_id,
            stats["synced"],
            stats["errors"],
            stats["skipped"],
        )

        return stats
