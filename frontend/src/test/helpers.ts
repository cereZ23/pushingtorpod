import { vi } from 'vitest'

/**
 * Create a mock Axios-like API client for store/service tests.
 *
 * Usage:
 *   vi.mock('@/api/client', () => ({ default: mockApiClient() }))
 */
export function mockApiClient() {
  return {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
    defaults: { baseURL: 'http://test' },
  }
}

/**
 * Create a mock vue-router instance for component tests.
 *
 * Usage:
 *   const router = mockRouter()
 *   mount(Component, { global: { mocks: { $router: router } } })
 */
export function mockRouter() {
  return {
    push: vi.fn(),
    replace: vi.fn(),
    go: vi.fn(),
    back: vi.fn(),
    currentRoute: { value: { path: '/', params: {}, query: {} } },
  }
}
