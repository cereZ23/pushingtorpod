import { vi, describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// Mock the tenantApi module
vi.mock('@/api/tenants', () => ({
  tenantApi: {
    list: vi.fn(),
    get: vi.fn(),
    getDashboard: vi.fn(),
  },
}))

// Mock the API client (needed because tenantApi imports it)
vi.mock('@/api/client', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: 'http://test' },
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
}))

import { tenantApi } from '@/api/tenants'
import { useTenantStore } from './tenant'
import type { Tenant } from '@/api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeTenant(overrides: Partial<Tenant> = {}): Tenant {
  return {
    id: 1,
    name: 'Default Tenant',
    slug: 'default',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('tenant store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    localStorage.clear()
  })

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------
  describe('initial state', () => {
    it('has null currentTenant and empty tenants list', () => {
      const store = useTenantStore()
      expect(store.currentTenant).toBeNull()
      expect(store.tenants).toEqual([])
      expect(store.currentTenantId).toBeUndefined()
    })
  })

  // -----------------------------------------------------------------------
  // selectTenant
  // -----------------------------------------------------------------------
  describe('selectTenant', () => {
    it('updates currentTenant when tenant exists in list', () => {
      const store = useTenantStore()
      store.tenants = [
        makeTenant({ id: 1, name: 'Tenant A' }),
        makeTenant({ id: 2, name: 'Tenant B' }),
      ]

      store.selectTenant(2)

      expect(store.currentTenant?.id).toBe(2)
      expect(store.currentTenant?.name).toBe('Tenant B')
      expect(store.currentTenantId).toBe(2)
    })

    it('persists tenant id to localStorage', () => {
      const store = useTenantStore()
      store.tenants = [makeTenant({ id: 5 })]

      store.selectTenant(5)

      expect(localStorage.getItem('currentTenantId')).toBe('5')
    })

    it('does not update when tenant id is not in list', () => {
      const store = useTenantStore()
      store.tenants = [makeTenant({ id: 1 })]
      store.selectTenant(1) // Select tenant 1 first

      store.selectTenant(999)

      // Should remain on the previously selected tenant
      expect(store.currentTenant?.id).toBe(1)
    })
  })

  // -----------------------------------------------------------------------
  // fetchTenants
  // -----------------------------------------------------------------------
  describe('fetchTenants', () => {
    it('loads tenants and auto-selects the first one', async () => {
      const tenants = [
        makeTenant({ id: 1, name: 'First' }),
        makeTenant({ id: 2, name: 'Second' }),
      ]
      vi.mocked(tenantApi.list).mockResolvedValueOnce(tenants)

      const store = useTenantStore()
      await store.fetchTenants()

      expect(store.tenants).toHaveLength(2)
      expect(store.currentTenant?.id).toBe(1)
      expect(store.currentTenantId).toBe(1)
    })

    it('restores previously selected tenant from localStorage', async () => {
      localStorage.setItem('currentTenantId', '2')

      const tenants = [
        makeTenant({ id: 1, name: 'First' }),
        makeTenant({ id: 2, name: 'Second' }),
      ]
      vi.mocked(tenantApi.list).mockResolvedValueOnce(tenants)

      const store = useTenantStore()
      await store.fetchTenants()

      expect(store.currentTenant?.id).toBe(2)
    })

    it('falls back to first tenant when stored id is not found', async () => {
      localStorage.setItem('currentTenantId', '999')

      const tenants = [makeTenant({ id: 1, name: 'Only One' })]
      vi.mocked(tenantApi.list).mockResolvedValueOnce(tenants)

      const store = useTenantStore()
      await store.fetchTenants()

      expect(store.currentTenant?.id).toBe(1)
    })

    it('does not change currentTenant if one is already selected', async () => {
      const tenants = [
        makeTenant({ id: 1, name: 'First' }),
        makeTenant({ id: 2, name: 'Second' }),
      ]
      vi.mocked(tenantApi.list).mockResolvedValueOnce(tenants)

      const store = useTenantStore()
      // Pre-set a current tenant
      store.currentTenant = makeTenant({ id: 2, name: 'Second' })

      await store.fetchTenants()

      // Should remain on tenant 2
      expect(store.currentTenant?.id).toBe(2)
    })

    it('handles empty tenant list', async () => {
      vi.mocked(tenantApi.list).mockResolvedValueOnce([])

      const store = useTenantStore()
      await store.fetchTenants()

      expect(store.tenants).toEqual([])
      expect(store.currentTenant).toBeNull()
    })
  })
})
