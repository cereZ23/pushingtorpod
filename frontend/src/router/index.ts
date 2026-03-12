import { createRouter, createWebHistory } from "vue-router";
import { useAuthStore } from "@/stores/auth";

declare module "vue-router" {
  interface RouteMeta {
    title?: string;
    requiresAuth?: boolean;
    requiresAdmin?: boolean;
  }
}

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/login",
      name: "Login",
      component: () => import("@/views/auth/LoginView.vue"),
      meta: { requiresAuth: false, title: "Login" },
    },
    {
      path: "/forgot-password",
      name: "ForgotPassword",
      component: () => import("@/views/auth/ForgotPasswordView.vue"),
      meta: { requiresAuth: false, title: "Forgot Password" },
    },
    {
      path: "/reset-password",
      name: "ResetPassword",
      component: () => import("@/views/auth/ResetPasswordView.vue"),
      meta: { requiresAuth: false, title: "Reset Password" },
    },
    {
      path: "/accept-invite",
      name: "AcceptInvite",
      component: () => import("@/views/auth/AcceptInviteView.vue"),
      meta: { requiresAuth: false, title: "Accept Invitation" },
    },
    {
      path: "/auth/sso-callback",
      name: "SsoCallback",
      component: () => import("@/views/auth/SsoCallbackView.vue"),
      meta: { requiresAuth: false, title: "SSO Login" },
    },
    {
      path: "/",
      component: () => import("@/layouts/DashboardLayout.vue"),
      meta: { requiresAuth: true },
      children: [
        {
          path: "",
          name: "Dashboard",
          component: () => import("@/views/dashboard/DashboardView.vue"),
          meta: { title: "Dashboard" },
        },
        {
          path: "assets",
          name: "AssetList",
          component: () => import("@/views/assets/AssetsView.vue"),
          meta: { title: "Assets" },
        },
        {
          path: "assets/:id",
          name: "AssetDetail",
          component: () => import("@/views/assets/AssetDetailView.vue"),
          meta: { title: "Asset Detail" },
        },
        {
          path: "findings",
          name: "FindingList",
          component: () => import("@/views/findings/FindingsView.vue"),
          meta: { title: "Findings" },
        },
        {
          path: "findings/:id",
          name: "FindingDetail",
          component: () => import("@/views/findings/FindingDetailView.vue"),
          meta: { title: "Finding Detail" },
        },
        {
          path: "certificates",
          name: "CertificateList",
          component: () => import("@/views/certificates/CertificatesView.vue"),
          meta: { title: "Certificates" },
        },
        {
          path: "certificates/:id",
          name: "CertificateDetail",
          component: () =>
            import("@/views/certificates/CertificateDetailView.vue"),
          meta: { title: "Certificate Detail" },
        },
        {
          path: "services",
          name: "ServiceList",
          component: () => import("@/views/services/ServicesView.vue"),
          meta: { title: "Services" },
        },
        {
          path: "scans",
          name: "Scans",
          component: () => import("@/views/scans/ScanManagement.vue"),
          meta: { title: "Scans" },
        },
        {
          path: "scans/:runId",
          name: "ScanDetail",
          component: () => import("@/views/scans/ScanDetail.vue"),
          meta: { title: "Scan Detail" },
        },
        {
          path: "issues",
          name: "Issues",
          component: () => import("@/views/issues/IssuesView.vue"),
          meta: { title: "Issues" },
        },
        {
          path: "issues/:id",
          name: "IssueDetail",
          component: () => import("@/views/issues/IssueDetail.vue"),
          meta: { title: "Issue Detail" },
        },
        {
          path: "graph",
          name: "SurfaceMap",
          component: () => import("@/views/graph/SurfaceMap.vue"),
          meta: { title: "Surface Map" },
        },
        {
          path: "geomap",
          name: "GeoMap",
          component: () => import("@/views/geomap/GeoMapView.vue"),
          meta: { title: "Geo Map" },
        },
        {
          path: "exposure",
          name: "Exposure",
          component: () => import("@/views/exposure/ExposureView.vue"),
          meta: { title: "Exposure" },
        },
        {
          path: "reports",
          name: "Reports",
          component: () => import("@/views/reports/ReportsView.vue"),
          meta: { title: "Reports" },
        },
        {
          path: "alerts",
          name: "AlertPolicies",
          component: () => import("@/views/alerts/AlertPolicies.vue"),
          meta: { title: "Alert Policies" },
        },
        {
          path: "settings/scan-policies",
          name: "ScanPolicies",
          component: () => import("@/views/settings/ScanPolicies.vue"),
          meta: { title: "Scan Policies" },
        },
        {
          path: "settings/suppressions",
          name: "SuppressionRules",
          component: () => import("@/views/settings/SuppressionRules.vue"),
          meta: { title: "Suppression Rules" },
        },
        {
          path: "settings/users",
          name: "Users",
          component: () => import("@/views/settings/UsersView.vue"),
          meta: { requiresAdmin: true, title: "User Management" },
        },
        {
          path: "settings/integrations",
          name: "Integrations",
          component: () => import("@/views/settings/IntegrationsView.vue"),
          meta: { requiresAdmin: true, title: "Integrations" },
        },
        {
          path: "settings/siem-export",
          name: "SiemExport",
          component: () => import("@/views/settings/SiemExportView.vue"),
          meta: { requiresAdmin: true, title: "SIEM Export" },
        },
        {
          path: "settings/security",
          name: "SecuritySettings",
          component: () => import("@/views/settings/SecuritySettingsView.vue"),
          meta: { title: "Security Settings" },
        },
        {
          path: "settings/report-schedules",
          name: "ReportSchedules",
          component: () => import("@/views/settings/ReportSchedulesView.vue"),
          meta: { title: "Scheduled Reports" },
        },
        {
          path: "settings/audit-log",
          name: "AuditLog",
          component: () => import("@/views/settings/AuditLogView.vue"),
          meta: { requiresAdmin: true, title: "Audit Log" },
        },
        {
          path: "admin/onboard-customer",
          name: "OnboardCustomer",
          component: () => import("@/views/admin/OnboardCustomerView.vue"),
          meta: { requiresAdmin: true, title: "Onboard Customer" },
        },
      ],
    },
    {
      path: "/:pathMatch(.*)*",
      name: "NotFound",
      component: () => import("@/views/NotFoundView.vue"),
      meta: { title: "Page Not Found" },
    },
  ],
});

// Page title management
router.afterEach((to) => {
  const title = to.meta.title;
  document.title = title ? `${title} - EASM Platform` : "EASM Platform";
});

// Navigation guard
router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore();

  // Check authentication
  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next("/login");
    return;
  }

  if (to.path === "/login" && authStore.isAuthenticated) {
    next("/");
    return;
  }

  // Check admin requirement (tenant-level or superuser)
  if (to.meta.requiresAdmin) {
    // Fetch user if not loaded yet
    if (!authStore.currentUser && authStore.isAuthenticated) {
      try {
        await authStore.fetchCurrentUser();
      } catch (error) {
        console.error("Failed to fetch user:", error);
        next("/login");
        return;
      }
    }

    if (!authStore.canAdmin) {
      console.warn("Access denied: Admin required");
      next("/");
      return;
    }
  }

  next();
});

export default router;
