import axios from 'axios'
import type { AxiosInstance } from 'axios'
import { useAuthStore } from '@/stores/auth'
import { useToastStore } from '@/stores/toast'
import router from '@/router'

const apiClient: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:18000',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor - Add auth token
apiClient.interceptors.request.use(
  (config) => {
    const authStore = useAuthStore()
    if (authStore.accessToken) {
      config.headers.Authorization = `Bearer ${authStore.accessToken}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response interceptor - Handle token refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config

    // Don't retry if this is already a refresh request
    if (originalRequest.url?.includes('/auth/refresh')) {
      const authStore = useAuthStore()
      authStore.clearTokens()
      router.push('/login')
      return Promise.reject(error)
    }

    // Handle 401 errors (expired/invalid token) - 403 is authorization, not authentication
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true

      const authStore = useAuthStore()

      try {
        await authStore.refreshAccessToken()
        // Retry original request with new token
        originalRequest.headers.Authorization = `Bearer ${authStore.accessToken}`
        return apiClient(originalRequest)
      } catch (refreshError) {
        // Refresh failed, logout user
        authStore.clearTokens()
        router.push('/login')
        return Promise.reject(refreshError)
      }
    }

    // Surface the failures that individual views typically DON'T handle, so a
    // background/async action can't fail completely silently. 4xx (incl. 403)
    // are left to callers to avoid double messaging; cancellations are ignored.
    if (!axios.isCancel(error) && originalRequest?._toastSilent !== true) {
      const status = error.response?.status
      if (!error.response) {
        useToastStore().error(
          error.code === 'ECONNABORTED'
            ? 'Request timed out — please retry.'
            : 'Network error — could not reach the server.',
        )
      } else if (typeof status === 'number' && status >= 500) {
        useToastStore().error(`Server error (${status}) — please try again.`)
      }
    }

    return Promise.reject(error)
  }
)

export default apiClient
