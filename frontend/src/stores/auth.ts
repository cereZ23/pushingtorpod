import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import type { User, LoginRequest, LoginResponse, LoginMfaResponse } from '@/api/types'
import { authApi } from '@/api/auth'
import router from '@/router'

export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const accessToken = ref<string | null>(localStorage.getItem('accessToken'))
  const refreshToken = ref<string | null>(localStorage.getItem('refreshToken'))

  // MFA flow state
  const mfaRequired = ref(false)
  const mfaToken = ref<string | null>(null)

  const isAuthenticated = computed(() => !!accessToken.value)
  const currentUser = computed(() => user.value)

  // RBAC helpers
  const currentTenantId = computed((): number | null => {
    const stored = localStorage.getItem('currentTenantId')
    return stored ? Number(stored) : null
  })

  const currentRole = computed((): string | null => {
    if (!user.value?.tenant_roles || !currentTenantId.value) return null
    return user.value.tenant_roles[currentTenantId.value] ?? null
  })

  const canWrite = computed((): boolean => {
    if (user.value?.is_superuser) return true
    const role = currentRole.value
    return role === 'analyst' || role === 'admin' || role === 'owner' || role === 'member'
  })

  const canAdmin = computed((): boolean => {
    if (user.value?.is_superuser) return true
    const role = currentRole.value
    return role === 'admin' || role === 'owner'
  })

  async function login(credentials: LoginRequest) {
    const response: LoginResponse | LoginMfaResponse = await authApi.login(credentials)

    // Handle MFA challenge
    if ('mfa_required' in response && response.mfa_required) {
      mfaRequired.value = true
      mfaToken.value = response.mfa_token
      return
    }

    const loginResponse = response as LoginResponse
    setTokens(loginResponse.access_token, loginResponse.refresh_token)
    user.value = loginResponse.user
    mfaRequired.value = false
    mfaToken.value = null
    localStorage.removeItem('currentTenantId')
    router.push('/')
  }

  async function verifyMfa(code: string) {
    if (!mfaToken.value) throw new Error('No MFA token')
    const response = await authApi.verifyMfa(mfaToken.value, code)
    setTokens(response.access_token, response.refresh_token)
    user.value = response.user
    mfaRequired.value = false
    mfaToken.value = null
    localStorage.removeItem('currentTenantId')
    router.push('/')
  }

  async function logout() {
    try {
      await authApi.logout()
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      clearTokens()
      router.push('/login')
    }
  }

  async function refreshAccessToken() {
    if (!refreshToken.value) {
      throw new Error('No refresh token available')
    }
    const response = await authApi.refresh(refreshToken.value)
    setTokens(response.access_token, response.refresh_token)
  }

  async function fetchCurrentUser() {
    user.value = await authApi.me()
  }

  function setTokens(access: string, refresh: string) {
    accessToken.value = access
    refreshToken.value = refresh
    localStorage.setItem('accessToken', access)
    localStorage.setItem('refreshToken', refresh)
  }

  function clearTokens() {
    accessToken.value = null
    refreshToken.value = null
    user.value = null
    mfaRequired.value = false
    mfaToken.value = null
    localStorage.removeItem('accessToken')
    localStorage.removeItem('refreshToken')
    localStorage.removeItem('currentTenantId')
  }

  return {
    user,
    accessToken,
    refreshToken,
    mfaRequired,
    mfaToken,
    isAuthenticated,
    currentUser,
    currentTenantId,
    currentRole,
    canWrite,
    canAdmin,
    login,
    verifyMfa,
    logout,
    refreshAccessToken,
    fetchCurrentUser,
    setTokens,
    clearTokens,
  }
})
