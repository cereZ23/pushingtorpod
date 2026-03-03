import '@testing-library/jest-dom'
import { beforeEach } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

// Polyfill localStorage for happy-dom environment.
// Node's built-in localStorage (--localstorage-file) does not implement the
// Web Storage API. We replace it with a simple in-memory implementation that
// mirrors the browser behaviour expected by the stores.
if (typeof globalThis.localStorage === 'undefined' || typeof globalThis.localStorage.clear !== 'function') {
  const storage = new Map<string, string>()
  const localStoragePolyfill: Storage = {
    get length() {
      return storage.size
    },
    clear() {
      storage.clear()
    },
    getItem(key: string) {
      return storage.get(key) ?? null
    },
    key(index: number) {
      return [...storage.keys()][index] ?? null
    },
    removeItem(key: string) {
      storage.delete(key)
    },
    setItem(key: string, value: string) {
      storage.set(key, String(value))
    },
  }
  Object.defineProperty(globalThis, 'localStorage', { value: localStoragePolyfill, writable: true })
}

// Reset Pinia before each test
beforeEach(() => {
  setActivePinia(createPinia())
})
