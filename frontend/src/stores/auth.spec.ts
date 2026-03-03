import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import type { User, LoginResponse, LoginMfaResponse, RefreshResponse } from '@/api/types'

// Polyfill localStorage for Node.js 25+ where native localStorage lacks Web Storage API methods
if (typeof globalThis.localStorage === 'undefined' || typeof globalThis.localStorage.getItem !== 'function') {
  const store = new Map<string, string>()
  globalThis.localStorage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => { store.set(key, String(value)) },
    removeItem: (key: string) => { store.delete(key) },
    clear: () => { store.clear() },
    get length() { return store.size },
    key: (index: number) => [...store.keys()][index] ?? null,
  } as Storage
}

// vi.hoisted runs before vi.mock factories, so these are available at hoist time
const {
  mockRouterPush,
  mockLogin,
  mockLogout,
  mockRefresh,
  mockMe,
  mockVerifyMfa,
} = vi.hoisted(() => ({
  mockRouterPush: vi.fn(),
  mockLogin: vi.fn(),
  mockLogout: vi.fn(),
  mockRefresh: vi.fn(),
  mockMe: vi.fn(),
  mockVerifyMfa: vi.fn(),
}))

// Mock the router module
vi.mock('@/router', () => ({
  default: { push: mockRouterPush },
}))

// Mock the auth API module
vi.mock('@/api/auth', () => ({
  authApi: {
    login: (...args: unknown[]) => mockLogin(...args),
    logout: (...args: unknown[]) => mockLogout(...args),
    refresh: (...args: unknown[]) => mockRefresh(...args),
    me: (...args: unknown[]) => mockMe(...args),
    verifyMfa: (...args: unknown[]) => mockVerifyMfa(...args),
  },
}))

// Import after mocks are set up (vitest hoists vi.mock above imports)
import { useAuthStore } from '@/stores/auth'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function createMockUser(overrides: Partial<User> = {}): User {
  return {
    id: 1,
    email: 'admin@easm.io',
    username: 'admin',
    full_name: 'Admin User',
    is_active: true,
    is_superuser: false,
    mfa_enabled: false,
    tenant_roles: { 1: 'admin' },
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

function createLoginResponse(overrides: Partial<LoginResponse> = {}): LoginResponse {
  return {
    access_token: 'test-access-token',
    refresh_token: 'test-refresh-token',
    token_type: 'bearer',
    expires_in: 3600,
    user: createMockUser(),
    ...overrides,
  }
}

function createMfaResponse(): LoginMfaResponse {
  return {
    mfa_required: true,
    mfa_token: 'mfa-challenge-token-123',
  }
}

function createRefreshResponse(overrides: Partial<RefreshResponse> = {}): RefreshResponse {
  return {
    access_token: 'new-access-token',
    refresh_token: 'new-refresh-token',
    token_type: 'bearer',
    expires_in: 3600,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('useAuthStore', () => {
  function clearLocalStorage() {
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    localStorage.removeItem('currentTenantId')
  }

  beforeEach(() => {
    setActivePinia(createPinia())
    clearLocalStorage()
    vi.clearAllMocks()
  })

  afterEach(() => {
    clearLocalStorage()
  })

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------

  describe('initial state', () => {
    it('starts with null user and no tokens', () => {
      const store = useAuthStore()

      expect(store.user).toBeNull()
      expect(store.accessToken).toBeNull()
      expect(store.refreshToken).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(store.mfaRequired).toBe(false)
      expect(store.mfaToken).toBeNull()
    })

    it('restores tokens from localStorage on creation', () => {
      localStorage.setItem('accessToken', 'stored-access')
      localStorage.setItem('refreshToken', 'stored-refresh')

      // Need a fresh Pinia so the store re-initializes
      setActivePinia(createPinia())
      const store = useAuthStore()

      expect(store.accessToken).toBe('stored-access')
      expect(store.refreshToken).toBe('stored-refresh')
      expect(store.isAuthenticated).toBe(true)
    })
  })

  // -----------------------------------------------------------------------
  // Login flow
  // -----------------------------------------------------------------------

  describe('login', () => {
    it('sets user, tokens, and isAuthenticated on success', async () => {
      const loginResponse = createLoginResponse()
      mockLogin.mockResolvedValueOnce(loginResponse)

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })

      expect(store.user).toEqual(loginResponse.user)
      expect(store.accessToken).toBe('test-access-token')
      expect(store.refreshToken).toBe('test-refresh-token')
      expect(store.isAuthenticated).toBe(true)
      expect(store.mfaRequired).toBe(false)
      expect(store.mfaToken).toBeNull()
    })

    it('stores tokens in localStorage', async () => {
      mockLogin.mockResolvedValueOnce(createLoginResponse())

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })

      expect(localStorage.getItem('accessToken')).toBe('test-access-token')
      expect(localStorage.getItem('refreshToken')).toBe('test-refresh-token')
    })

    it('navigates to root after successful login', async () => {
      mockLogin.mockResolvedValueOnce(createLoginResponse())

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })

      expect(mockRouterPush).toHaveBeenCalledWith('/')
    })

    it('clears currentTenantId from localStorage on login', async () => {
      localStorage.setItem('currentTenantId', '5')
      mockLogin.mockResolvedValueOnce(createLoginResponse())

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })

      expect(localStorage.getItem('currentTenantId')).toBeNull()
    })

    it('throws error on invalid credentials', async () => {
      const apiError = new Error('Invalid credentials')
      mockLogin.mockRejectedValueOnce(apiError)

      const store = useAuthStore()

      await expect(
        store.login({ email: 'bad@easm.io', password: 'wrong' })
      ).rejects.toThrow('Invalid credentials')

      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(store.accessToken).toBeNull()
    })

    it('passes credentials to authApi.login', async () => {
      mockLogin.mockResolvedValueOnce(createLoginResponse())

      const store = useAuthStore()
      const credentials = { email: 'admin@easm.io', password: 'secret' }
      await store.login(credentials)

      expect(mockLogin).toHaveBeenCalledWith(credentials)
    })
  })

  // -----------------------------------------------------------------------
  // MFA flow
  // -----------------------------------------------------------------------

  describe('MFA flow', () => {
    it('sets mfaRequired and mfaToken when MFA is needed', async () => {
      mockLogin.mockResolvedValueOnce(createMfaResponse())

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })

      expect(store.mfaRequired).toBe(true)
      expect(store.mfaToken).toBe('mfa-challenge-token-123')
      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(mockRouterPush).not.toHaveBeenCalled()
    })

    it('does not set tokens or user when MFA is required', async () => {
      mockLogin.mockResolvedValueOnce(createMfaResponse())

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })

      expect(store.accessToken).toBeNull()
      expect(store.refreshToken).toBeNull()
      expect(localStorage.getItem('accessToken')).toBeNull()
      expect(localStorage.getItem('refreshToken')).toBeNull()
    })

    it('completes login after verifyMfa with valid code', async () => {
      const loginResponse = createLoginResponse()
      mockLogin.mockResolvedValueOnce(createMfaResponse())
      mockVerifyMfa.mockResolvedValueOnce(loginResponse)

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })
      await store.verifyMfa('123456')

      expect(mockVerifyMfa).toHaveBeenCalledWith('mfa-challenge-token-123', '123456')
      expect(store.user).toEqual(loginResponse.user)
      expect(store.accessToken).toBe('test-access-token')
      expect(store.refreshToken).toBe('test-refresh-token')
      expect(store.isAuthenticated).toBe(true)
      expect(store.mfaRequired).toBe(false)
      expect(store.mfaToken).toBeNull()
      expect(mockRouterPush).toHaveBeenCalledWith('/')
    })

    it('throws error on verifyMfa with invalid code', async () => {
      mockLogin.mockResolvedValueOnce(createMfaResponse())
      mockVerifyMfa.mockRejectedValueOnce(new Error('Invalid TOTP code'))

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })

      await expect(store.verifyMfa('000000')).rejects.toThrow('Invalid TOTP code')
      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
    })

    it('throws error when verifyMfa called without mfaToken', async () => {
      const store = useAuthStore()

      await expect(store.verifyMfa('123456')).rejects.toThrow('No MFA token')
    })

    it('clears currentTenantId after successful MFA verification', async () => {
      localStorage.setItem('currentTenantId', '3')
      mockLogin.mockResolvedValueOnce(createMfaResponse())
      mockVerifyMfa.mockResolvedValueOnce(createLoginResponse())

      const store = useAuthStore()
      await store.login({ email: 'admin@easm.io', password: 'secret' })
      await store.verifyMfa('123456')

      expect(localStorage.getItem('currentTenantId')).toBeNull()
    })
  })

  // -----------------------------------------------------------------------
  // Token management
  // -----------------------------------------------------------------------

  describe('token management', () => {
    it('refreshAccessToken updates the access token', async () => {
      const refreshResponse = createRefreshResponse()
      mockRefresh.mockResolvedValueOnce(refreshResponse)

      const store = useAuthStore()
      store.setTokens('old-access', 'old-refresh')

      await store.refreshAccessToken()

      expect(mockRefresh).toHaveBeenCalledWith('old-refresh')
      expect(store.accessToken).toBe('new-access-token')
      expect(store.refreshToken).toBe('new-refresh-token')
      expect(localStorage.getItem('accessToken')).toBe('new-access-token')
      expect(localStorage.getItem('refreshToken')).toBe('new-refresh-token')
    })

    it('refreshAccessToken throws when no refresh token available', async () => {
      const store = useAuthStore()

      await expect(store.refreshAccessToken()).rejects.toThrow(
        'No refresh token available'
      )
      expect(mockRefresh).not.toHaveBeenCalled()
    })

    it('clearTokens removes all auth state', () => {
      const store = useAuthStore()
      store.setTokens('some-access', 'some-refresh')
      store.user = createMockUser()
      localStorage.setItem('currentTenantId', '1')

      store.clearTokens()

      expect(store.accessToken).toBeNull()
      expect(store.refreshToken).toBeNull()
      expect(store.user).toBeNull()
      expect(store.mfaRequired).toBe(false)
      expect(store.mfaToken).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(localStorage.getItem('accessToken')).toBeNull()
      expect(localStorage.getItem('refreshToken')).toBeNull()
      expect(localStorage.getItem('currentTenantId')).toBeNull()
    })

    it('setTokens stores tokens in state and localStorage', () => {
      const store = useAuthStore()

      store.setTokens('my-access', 'my-refresh')

      expect(store.accessToken).toBe('my-access')
      expect(store.refreshToken).toBe('my-refresh')
      expect(localStorage.getItem('accessToken')).toBe('my-access')
      expect(localStorage.getItem('refreshToken')).toBe('my-refresh')
    })
  })

  // -----------------------------------------------------------------------
  // Logout
  // -----------------------------------------------------------------------

  describe('logout', () => {
    it('calls authApi.logout and clears tokens', async () => {
      mockLogout.mockResolvedValueOnce(undefined)

      const store = useAuthStore()
      store.setTokens('access', 'refresh')
      store.user = createMockUser()

      await store.logout()

      expect(mockLogout).toHaveBeenCalled()
      expect(store.accessToken).toBeNull()
      expect(store.refreshToken).toBeNull()
      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
    })

    it('navigates to /login after logout', async () => {
      mockLogout.mockResolvedValueOnce(undefined)

      const store = useAuthStore()
      await store.logout()

      expect(mockRouterPush).toHaveBeenCalledWith('/login')
    })

    it('clears tokens even when API logout fails', async () => {
      mockLogout.mockRejectedValueOnce(new Error('Network error'))
      // Suppress expected console.error from the store's catch block
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      const store = useAuthStore()
      store.setTokens('access', 'refresh')
      store.user = createMockUser()

      await store.logout()
      consoleSpy.mockRestore()

      expect(store.accessToken).toBeNull()
      expect(store.user).toBeNull()
      expect(store.isAuthenticated).toBe(false)
      expect(mockRouterPush).toHaveBeenCalledWith('/login')
    })
  })

  // -----------------------------------------------------------------------
  // fetchCurrentUser
  // -----------------------------------------------------------------------

  describe('fetchCurrentUser', () => {
    it('fetches and sets the current user', async () => {
      const mockUser = createMockUser({ email: 'fetched@easm.io' })
      mockMe.mockResolvedValueOnce(mockUser)

      const store = useAuthStore()
      await store.fetchCurrentUser()

      expect(store.user).toEqual(mockUser)
      expect(store.currentUser).toEqual(mockUser)
    })

    it('propagates API error', async () => {
      mockMe.mockRejectedValueOnce(new Error('Unauthorized'))

      const store = useAuthStore()

      await expect(store.fetchCurrentUser()).rejects.toThrow('Unauthorized')
    })
  })

  // -----------------------------------------------------------------------
  // RBAC computed properties
  // -----------------------------------------------------------------------

  describe('currentTenantId', () => {
    it('returns null when not set', () => {
      const store = useAuthStore()
      expect(store.currentTenantId).toBeNull()
    })

    it('reads currentTenantId from localStorage', () => {
      localStorage.setItem('currentTenantId', '42')
      const store = useAuthStore()
      expect(store.currentTenantId).toBe(42)
    })
  })

  describe('currentRole', () => {
    it('returns null when user is null', () => {
      const store = useAuthStore()
      expect(store.currentRole).toBeNull()
    })

    it('returns null when currentTenantId is not set', () => {
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin' } })
      // No currentTenantId in localStorage
      expect(store.currentRole).toBeNull()
    })

    it('returns role for current tenant', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin', 2: 'viewer' } })

      expect(store.currentRole).toBe('admin')
    })

    it('returns role for a different tenant', () => {
      localStorage.setItem('currentTenantId', '2')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin', 2: 'viewer' } })

      expect(store.currentRole).toBe('viewer')
    })

    it('returns null when user has no role for current tenant', () => {
      localStorage.setItem('currentTenantId', '99')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin' } })

      expect(store.currentRole).toBeNull()
    })

    it('returns null when tenant_roles is undefined', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: undefined })

      expect(store.currentRole).toBeNull()
    })
  })

  describe('canWrite', () => {
    it('returns true for analyst role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'analyst' } })

      expect(store.canWrite).toBe(true)
    })

    it('returns true for admin role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin' } })

      expect(store.canWrite).toBe(true)
    })

    it('returns true for owner role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'owner' } })

      expect(store.canWrite).toBe(true)
    })

    it('returns true for member role (legacy)', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'member' } })

      expect(store.canWrite).toBe(true)
    })

    it('returns false for viewer role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'viewer' } })

      expect(store.canWrite).toBe(false)
    })

    it('returns true for superuser regardless of role', () => {
      const store = useAuthStore()
      store.user = createMockUser({ is_superuser: true, tenant_roles: {} })

      expect(store.canWrite).toBe(true)
    })

    it('returns false when no user is set', () => {
      const store = useAuthStore()
      expect(store.canWrite).toBe(false)
    })

    it('returns false when no currentTenantId and not superuser', () => {
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin' } })
      // No currentTenantId in localStorage -> currentRole is null

      expect(store.canWrite).toBe(false)
    })
  })

  describe('canAdmin', () => {
    it('returns true for admin role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin' } })

      expect(store.canAdmin).toBe(true)
    })

    it('returns true for owner role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'owner' } })

      expect(store.canAdmin).toBe(true)
    })

    it('returns false for analyst role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'analyst' } })

      expect(store.canAdmin).toBe(false)
    })

    it('returns false for viewer role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'viewer' } })

      expect(store.canAdmin).toBe(false)
    })

    it('returns false for member role', () => {
      localStorage.setItem('currentTenantId', '1')
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'member' } })

      expect(store.canAdmin).toBe(false)
    })

    it('returns true for superuser regardless of role', () => {
      const store = useAuthStore()
      store.user = createMockUser({ is_superuser: true, tenant_roles: {} })

      expect(store.canAdmin).toBe(true)
    })

    it('returns false when no user is set', () => {
      const store = useAuthStore()
      expect(store.canAdmin).toBe(false)
    })

    it('returns false when no currentTenantId and not superuser', () => {
      const store = useAuthStore()
      store.user = createMockUser({ tenant_roles: { 1: 'admin' } })

      expect(store.canAdmin).toBe(false)
    })
  })

  // -----------------------------------------------------------------------
  // isAuthenticated computed
  // -----------------------------------------------------------------------

  describe('isAuthenticated', () => {
    it('is true when accessToken is present', () => {
      const store = useAuthStore()
      store.setTokens('token', 'refresh')

      expect(store.isAuthenticated).toBe(true)
    })

    it('is false when accessToken is null', () => {
      const store = useAuthStore()
      expect(store.isAuthenticated).toBe(false)
    })

    it('is false after clearTokens', () => {
      const store = useAuthStore()
      store.setTokens('token', 'refresh')
      store.clearTokens()

      expect(store.isAuthenticated).toBe(false)
    })
  })

  // -----------------------------------------------------------------------
  // currentUser computed
  // -----------------------------------------------------------------------

  describe('currentUser', () => {
    it('returns the user ref value', () => {
      const store = useAuthStore()
      const mockUser = createMockUser()
      store.user = mockUser

      expect(store.currentUser).toEqual(mockUser)
    })

    it('returns null when no user is set', () => {
      const store = useAuthStore()
      expect(store.currentUser).toBeNull()
    })
  })
})
