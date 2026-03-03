import apiClient from './client'
import type { LoginRequest, LoginResponse, LoginMfaResponse, RefreshResponse, User } from './types'

export const authApi = {
  async login(credentials: LoginRequest): Promise<LoginResponse | LoginMfaResponse> {
    const response = await apiClient.post<LoginResponse | LoginMfaResponse>('/api/v1/auth/login', credentials)
    return response.data
  },

  async logout(): Promise<void> {
    await apiClient.post('/api/v1/auth/logout')
  },

  async refresh(refreshToken: string): Promise<RefreshResponse> {
    const response = await apiClient.post<RefreshResponse>('/api/v1/auth/refresh', {
      refresh_token: refreshToken,
    })
    return response.data
  },

  async me(): Promise<User> {
    const response = await apiClient.get<User>('/api/v1/auth/me')
    return response.data
  },

  async verifyMfa(mfaToken: string, code: string): Promise<LoginResponse> {
    const response = await apiClient.post<LoginResponse>('/api/v1/auth/mfa/verify', {
      mfa_token: mfaToken,
      code,
    })
    return response.data
  },

  async forgotPassword(email: string): Promise<void> {
    await apiClient.post('/api/v1/auth/forgot-password', { email })
  },

  async resetPassword(token: string, newPassword: string): Promise<void> {
    await apiClient.post('/api/v1/auth/reset-password', {
      token,
      new_password: newPassword,
    })
  },

  async acceptInvite(token: string, username: string, password: string, fullName?: string): Promise<User> {
    const response = await apiClient.post<User>('/api/v1/auth/accept-invite', {
      token,
      username,
      password,
      full_name: fullName || undefined,
    })
    return response.data
  },

  async setupMfa(): Promise<{ secret: string; provisioning_uri: string; qr_code_base64?: string }> {
    const response = await apiClient.post('/api/v1/auth/mfa/setup')
    return response.data
  },

  async verifyMfaSetup(code: string): Promise<void> {
    await apiClient.post('/api/v1/auth/mfa/verify-setup', { code })
  },

  async disableMfa(password: string): Promise<void> {
    await apiClient.post('/api/v1/auth/mfa/disable', { password })
  },
}
