import { describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useThemeStore } from './theme'

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('theme store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
    document.documentElement.classList.remove('dark')
  })

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------
  describe('initial state', () => {
    it('defaults to light theme', () => {
      const store = useThemeStore()
      expect(store.isDark).toBe(false)
    })
  })

  // -----------------------------------------------------------------------
  // toggleTheme
  // -----------------------------------------------------------------------
  describe('toggleTheme', () => {
    it('switches from light to dark', () => {
      const store = useThemeStore()
      expect(store.isDark).toBe(false)

      store.toggleTheme()

      expect(store.isDark).toBe(true)
      expect(localStorage.getItem('theme')).toBe('dark')
      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('switches from dark to light', () => {
      const store = useThemeStore()
      store.isDark = true
      document.documentElement.classList.add('dark')

      store.toggleTheme()

      expect(store.isDark).toBe(false)
      expect(localStorage.getItem('theme')).toBe('light')
      expect(document.documentElement.classList.contains('dark')).toBe(false)
    })

    it('toggles multiple times correctly', () => {
      const store = useThemeStore()

      store.toggleTheme() // -> dark
      expect(store.isDark).toBe(true)

      store.toggleTheme() // -> light
      expect(store.isDark).toBe(false)

      store.toggleTheme() // -> dark
      expect(store.isDark).toBe(true)
    })
  })

  // -----------------------------------------------------------------------
  // initTheme
  // -----------------------------------------------------------------------
  describe('initTheme', () => {
    it('reads stored "dark" preference from localStorage', () => {
      localStorage.setItem('theme', 'dark')

      const store = useThemeStore()
      store.initTheme()

      expect(store.isDark).toBe(true)
      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('reads stored "light" preference from localStorage', () => {
      localStorage.setItem('theme', 'light')

      const store = useThemeStore()
      store.initTheme()

      expect(store.isDark).toBe(false)
      expect(document.documentElement.classList.contains('dark')).toBe(false)
    })

    it('falls back to system preference when no stored value', () => {
      // happy-dom matchMedia defaults to not matching, so isDark should be false
      const store = useThemeStore()
      store.initTheme()

      expect(store.isDark).toBe(false)
    })

    it('applies dark class to document when dark mode is active', () => {
      localStorage.setItem('theme', 'dark')

      const store = useThemeStore()
      store.initTheme()

      expect(document.documentElement.classList.contains('dark')).toBe(true)
    })

    it('removes dark class from document when light mode is active', () => {
      document.documentElement.classList.add('dark')
      localStorage.setItem('theme', 'light')

      const store = useThemeStore()
      store.initTheme()

      expect(document.documentElement.classList.contains('dark')).toBe(false)
    })
  })
})
