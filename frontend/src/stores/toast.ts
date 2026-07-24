import { defineStore } from 'pinia'
import { ref } from 'vue'

export type ToastKind = 'success' | 'error' | 'info' | 'warning'

export interface Toast {
  id: number
  kind: ToastKind
  message: string
}

/**
 * App-wide toast notifications. Replaces the per-view hand-rolled success/error
 * banners and gives async/background failures (network, 5xx) a visible surface.
 */
export const useToastStore = defineStore('toast', () => {
  const toasts = ref<Toast[]>([])
  let seq = 0

  function dismiss(id: number): void {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }

  function push(kind: ToastKind, message: string, timeout = 4000): number {
    const id = ++seq
    toasts.value.push({ id, kind, message })
    if (timeout > 0) {
      window.setTimeout(() => dismiss(id), timeout)
    }
    return id
  }

  const success = (message: string, timeout?: number) => push('success', message, timeout)
  // Errors linger a bit longer so they aren't missed.
  const error = (message: string, timeout?: number) => push('error', message, timeout ?? 6000)
  const info = (message: string, timeout?: number) => push('info', message, timeout)
  const warning = (message: string, timeout?: number) => push('warning', message, timeout)

  return { toasts, push, dismiss, success, error, info, warning }
})
