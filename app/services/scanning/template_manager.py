"""
Nuclei template management service

Manages Nuclei templates including:
- Template discovery and listing
- Template updates
- Category filtering
- Template validation
- Custom template support
"""

import logging
import json
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from datetime import datetime, timezone

from app.utils.secure_executor import SecureToolExecutor, ToolExecutionError
from app.config import settings

logger = logging.getLogger(__name__)


class TemplateManager:
    """
    Manages Nuclei templates for vulnerability scanning

    Features:
    - List available templates
    - Filter by category/severity
    - Update templates from ProjectDiscovery repo
    - Validate custom templates
    - Template statistics
    """

    # Minimum number of template files expected on disk after a successful
    # update. The real corpus is ~10k+; anything below this means the templates
    # directory is empty or masked (a silent-failure guard).
    MIN_EXPECTED_TEMPLATES = 100

    # Template categories (aligned with Nuclei's directory structure)
    CATEGORIES = {
        "cves": {"path": "cves/", "description": "CVE-based vulnerabilities", "risk": "high"},
        "exposed-panels": {"path": "exposed-panels/", "description": "Exposed admin/login panels", "risk": "medium"},
        "misconfigurations": {
            "path": "misconfigurations/",
            "description": "Common misconfigurations",
            "risk": "medium",
        },
        "default-logins": {"path": "default-logins/", "description": "Default credentials", "risk": "high"},
        "takeovers": {"path": "takeovers/", "description": "Subdomain takeovers", "risk": "high"},
        "exposures": {"path": "exposures/", "description": "Information disclosure", "risk": "medium"},
        "technologies": {"path": "technologies/", "description": "Technology detection", "risk": "low"},
        "vulnerabilities": {"path": "vulnerabilities/", "description": "Generic vulnerabilities", "risk": "high"},
        "fuzzing": {"path": "fuzzing/", "description": "Fuzzing templates", "risk": "low"},
        "workflows": {"path": "workflows/", "description": "Workflow-based scans", "risk": "medium"},
    }

    def __init__(self, tenant_id: Optional[int] = None):
        """
        Initialize template manager

        Args:
            tenant_id: Optional tenant ID for custom templates
        """
        self.tenant_id = tenant_id

    def list_templates(
        self, categories: Optional[List[str]] = None, severity: Optional[List[str]] = None
    ) -> List[Dict]:
        """
        List available Nuclei templates

        Args:
            categories: Filter by categories
            severity: Filter by severity

        Returns:
            List of template info dicts
        """
        templates = []

        # Build filter arguments
        args = ["-tl"]  # Template list

        if categories:
            for category in categories:
                if category in self.CATEGORIES:
                    args.extend(["-t", self.CATEGORIES[category]["path"]])

        if severity:
            severity_str = ",".join(severity)
            args.extend(["-severity", severity_str])

        # Execute nuclei to list templates
        try:
            # Use system tenant (0) for template operations
            with SecureToolExecutor(0) as executor:
                returncode, stdout, stderr = executor.execute("nuclei", args, timeout=60)

                if returncode != 0:
                    logger.warning(f"Nuclei template list returned code {returncode}")

                # Parse output
                for line in stdout.strip().split("\n"):
                    if line and not line.startswith("["):  # Skip log lines
                        templates.append({"path": line.strip()})

        except ToolExecutionError as e:
            logger.error(f"Failed to list templates: {e}")

        return templates

    def update_templates(self) -> Dict:
        """
        Update Nuclei templates from ProjectDiscovery repository

        Returns:
            Dict with update results:
            {
                'success': bool,
                'templates_updated': int,
                'version': str,
                'timestamp': str
            }
        """
        logger.info("Updating Nuclei templates...")

        try:
            # Use system tenant (0) for template operations
            with SecureToolExecutor(0) as executor:
                returncode, stdout, stderr = executor.execute(
                    "nuclei",
                    ["-update-templates"],
                    timeout=300,  # 5 minutes for download
                )

                if returncode != 0:
                    logger.error(f"Template update failed: {stderr}")
                    return {"success": False, "error": stderr, "timestamp": datetime.now(timezone.utc).isoformat()}

                # HARDENING: a zero return code is NOT sufficient. nuclei reports
                # "No new updates" / exit 0 even when the templates directory is
                # empty (e.g. masked by an empty volume mount) — a silent failure
                # that makes every subsequent scan a false negative. Verify the
                # templates actually exist on disk before declaring success.
                template_count = self._count_templates_on_disk()
                if template_count < self.MIN_EXPECTED_TEMPLATES:
                    logger.error(
                        "Template update reported success but only %d templates are present "
                        "(expected >= %d) — the templates directory may be empty or masked.",
                        template_count,
                        self.MIN_EXPECTED_TEMPLATES,
                    )
                    return {
                        "success": False,
                        "error": (
                            f"only {template_count} templates present after update "
                            f"(expected >= {self.MIN_EXPECTED_TEMPLATES}); templates dir may be empty/masked"
                        ),
                        "template_count": template_count,
                        "output": stdout,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

                logger.info("Nuclei templates updated: %d templates present", template_count)
                return {
                    "success": True,
                    "template_count": template_count,
                    "output": stdout,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

        except ToolExecutionError as e:
            logger.error(f"Failed to update templates: {e}")
            return {"success": False, "error": str(e), "timestamp": datetime.now(timezone.utc).isoformat()}

    def _count_templates_on_disk(self) -> int:
        """Count nuclei template files (.yaml/.yml) actually present on disk.

        Robust check independent of nuclei's own output or template-path layout —
        a masked/empty templates directory yields 0, which the caller treats as a
        failed update rather than a silent success.
        """
        import os

        template_dir = os.environ.get("NUCLEI_TEMPLATES") or os.path.expanduser("~/nuclei-templates")
        count = 0
        try:
            for _root, _dirs, files in os.walk(template_dir):
                count += sum(1 for f in files if f.endswith((".yaml", ".yml")))
        except OSError as exc:
            logger.error("Could not read nuclei templates directory %s: %s", template_dir, exc)
            return 0
        return count

    def get_template_info(self, template_id: str) -> Optional[Dict]:
        """
        Get detailed information about a specific template

        Args:
            template_id: Template ID (e.g., 'CVE-2021-12345')

        Returns:
            Template info dict or None
        """
        try:
            with SecureToolExecutor(0) as executor:
                returncode, stdout, stderr = executor.execute(
                    "nuclei", ["-t", template_id, "-json", "-validate"], timeout=30
                )

                if returncode == 0 and stdout:
                    try:
                        return json.loads(stdout)
                    except json.JSONDecodeError:
                        pass

        except ToolExecutionError as e:
            logger.warning(f"Failed to get template info for {template_id}: {e}")

        return None

    def validate_template(self, template_content: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a custom Nuclei template

        Args:
            template_content: YAML template content

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            with SecureToolExecutor(0) as executor:
                # Write template to temp file
                template_file = executor.create_input_file("custom-template.yaml", template_content)

                # Validate template
                returncode, stdout, stderr = executor.execute("nuclei", ["-t", template_file, "-validate"], timeout=30)

                if returncode == 0:
                    return True, None
                else:
                    return False, stderr

        except ToolExecutionError as e:
            return False, str(e)

    def get_categories(self) -> Dict[str, Dict]:
        """
        Get available template categories

        Returns:
            Dict of category name to info
        """
        return self.CATEGORIES.copy()

    def get_recommended_templates(self, asset_type: str) -> List[str]:
        """
        Get recommended templates for asset type

        Args:
            asset_type: Asset type (web, api, subdomain, ip)

        Returns:
            List of recommended template paths
        """
        recommendations = {
            "web": ["cves/", "exposed-panels/", "misconfigurations/", "default-logins/", "exposures/"],
            "api": ["cves/", "misconfigurations/", "exposures/"],
            "subdomain": ["takeovers/", "dns/", "cves/"],
            "ip": ["cves/", "exposed-panels/", "default-logins/"],
        }

        return recommendations.get(asset_type, ["cves/", "vulnerabilities/"])

    def get_template_stats(self) -> Dict:
        """
        Get statistics about available templates

        Returns:
            Dict with template statistics
        """
        stats = {
            "total_templates": 0,
            "by_category": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "last_updated": None,
        }

        # Get template list
        templates = self.list_templates()
        stats["total_templates"] = len(templates)

        # Count by category
        for category_name, category_info in self.CATEGORIES.items():
            category_templates = self.list_templates(categories=[category_name])
            stats["by_category"][category_name] = len(category_templates)

        return stats


# Singleton instance for global use
template_manager = TemplateManager()
