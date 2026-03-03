"""
API Routers Package

Core API endpoint routers.
"""

from .auth import router as auth_router
from .tenants import router as tenants_router
from .assets import router as assets_router
from .services import router as services_router
from .certificates import router as certificates_router
from .endpoints import router as endpoints_router
from .findings import router as findings_router
from .onboarding import router as onboarding_router
from .scanning import router as scanning_router
from .projects import router as projects_router
from .dashboard import router as dashboard_router
from .graph import router as graph_router
from .issues import router as issues_router
from .alert_policies import router as alert_policies_router
from .reports import router as reports_router
from .suppressions import router as suppressions_router
from .threat_intel import admin_router as threat_intel_admin_router
from .threat_intel import tenant_router as threat_intel_tenant_router
from .tickets import router as tickets_router
from .saml import router as saml_router
from .siem import router as siem_router
from .report_schedules import router as report_schedules_router
from .users import router as users_router
from .users import invitations_router
from .search import router as search_router
from .audit import router as audit_router

__all__ = [
    "auth_router",
    "tenants_router",
    "assets_router",
    "services_router",
    "certificates_router",
    "endpoints_router",
    "findings_router",
    "onboarding_router",
    "scanning_router",
    "projects_router",
    "dashboard_router",
    "graph_router",
    "issues_router",
    "alert_policies_router",
    "reports_router",
    "suppressions_router",
    "threat_intel_admin_router",
    "threat_intel_tenant_router",
    "tickets_router",
    "saml_router",
    "siem_router",
    "report_schedules_router",
    "users_router",
    "invitations_router",
    "search_router",
    "audit_router",
]
