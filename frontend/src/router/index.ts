import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('@/views/auth/LoginView.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/onboarding',
      name: 'Onboarding',
      component: () => import('@/views/onboarding/OnboardingView.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/auth/sso-callback',
      name: 'SsoCallback',
      component: () => import('@/views/auth/SsoCallbackView.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/',
      component: () => import('@/layouts/DashboardLayout.vue'),
      meta: { requiresAuth: true },
      children: [
        {
          path: '',
          name: 'Dashboard',
          component: () => import('@/views/dashboard/DashboardView.vue'),
        },
        {
          path: 'assets',
          name: 'AssetList',
          component: () => import('@/views/assets/AssetsView.vue'),
        },
        {
          path: 'assets/:id',
          name: 'AssetDetail',
          component: () => import('@/views/assets/AssetDetailView.vue'),
        },
        {
          path: 'findings',
          name: 'FindingList',
          component: () => import('@/views/findings/FindingsView.vue'),
        },
        {
          path: 'findings/:id',
          name: 'FindingDetail',
          component: () => import('@/views/findings/FindingDetailView.vue'),
        },
        {
          path: 'certificates',
          name: 'CertificateList',
          component: () => import('@/views/certificates/CertificatesView.vue'),
        },
        {
          path: 'certificates/:id',
          name: 'CertificateDetail',
          component: () => import('@/views/certificates/CertificateDetailView.vue'),
        },
        {
          path: 'services',
          name: 'ServiceList',
          component: () => import('@/views/services/ServicesView.vue'),
        },
        {
          path: 'scans',
          name: 'Scans',
          component: () => import('@/views/scans/ScanManagement.vue'),
        },
        {
          path: 'scans/:runId',
          name: 'ScanDetail',
          component: () => import('@/views/scans/ScanDetail.vue'),
        },
        {
          path: 'issues',
          name: 'Issues',
          component: () => import('@/views/issues/IssuesView.vue'),
        },
        {
          path: 'issues/:id',
          name: 'IssueDetail',
          component: () => import('@/views/issues/IssueDetail.vue'),
        },
        {
          path: 'graph',
          name: 'SurfaceMap',
          component: () => import('@/views/graph/SurfaceMap.vue'),
        },
        {
          path: 'reports',
          name: 'Reports',
          component: () => import('@/views/reports/ReportsView.vue'),
        },
        {
          path: 'alerts',
          name: 'AlertPolicies',
          component: () => import('@/views/alerts/AlertPolicies.vue'),
        },
        {
          path: 'settings/scan-policies',
          name: 'ScanPolicies',
          component: () => import('@/views/settings/ScanPolicies.vue'),
        },
        {
          path: 'settings/suppressions',
          name: 'SuppressionRules',
          component: () => import('@/views/settings/SuppressionRules.vue'),
        },
        {
          path: 'admin/onboard-customer',
          name: 'OnboardCustomer',
          component: () => import('@/views/admin/OnboardCustomerView.vue'),
          meta: { requiresAdmin: true },
        },
      ],
    },
  ],
})

// Navigation guard
router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()

  // Check authentication
  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next('/login')
    return
  }

  if (to.path === '/login' && authStore.isAuthenticated) {
    next('/')
    return
  }

  // Check admin requirement
  if (to.meta.requiresAdmin) {
    // Fetch user if not loaded yet
    if (!authStore.currentUser && authStore.isAuthenticated) {
      try {
        await authStore.fetchCurrentUser()
      } catch (error) {
        console.error('Failed to fetch user:', error)
        next('/login')
        return
      }
    }

    // Check if user is admin (superuser)
    if (!authStore.currentUser?.is_superuser) {
      console.warn('Access denied: Admin required')
      next('/')
      return
    }
  }

  next()
})

export default router
