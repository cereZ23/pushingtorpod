<script setup lang="ts">
import { ref, watch, nextTick, onUnmounted } from 'vue'

interface Props {
  open: boolean
  title: string
  description?: string
}

const props = defineProps<Props>()
const emit = defineEmits<{ close: [] }>()

const dialogRef = ref<HTMLElement | null>(null)
let previouslyFocused: HTMLElement | null = null

function getFocusableElements(): HTMLElement[] {
  if (!dialogRef.value) return []
  return Array.from(
    dialogRef.value.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
    )
  )
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    emit('close')
    return
  }

  if (e.key === 'Tab') {
    const focusable = getFocusableElements()
    if (focusable.length === 0) return

    const first = focusable[0]
    const last = focusable[focusable.length - 1]

    if (e.shiftKey) {
      if (document.activeElement === first) {
        e.preventDefault()
        last.focus()
      }
    } else {
      if (document.activeElement === last) {
        e.preventDefault()
        first.focus()
      }
    }
  }
}

function handleBackdropClick(e: MouseEvent) {
  if (e.target === e.currentTarget) {
    emit('close')
  }
}

watch(
  () => props.open,
  async (isOpen) => {
    if (isOpen) {
      previouslyFocused = document.activeElement as HTMLElement | null
      await nextTick()
      const focusable = getFocusableElements()
      if (focusable.length > 0) {
        focusable[0].focus()
      } else {
        dialogRef.value?.focus()
      }
    } else {
      previouslyFocused?.focus()
      previouslyFocused = null
    }
  }
)

onUnmounted(() => {
  previouslyFocused = null
})
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="fixed inset-0 z-50 flex items-center justify-center"
      @click="handleBackdropClick"
      @keydown="handleKeydown"
    >
      <!-- Backdrop -->
      <div class="absolute inset-0 bg-black/50" aria-hidden="true" />

      <!-- Dialog -->
      <div
        ref="dialogRef"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="title ? 'dialog-title' : undefined"
        :aria-describedby="description ? 'dialog-description' : undefined"
        tabindex="-1"
        class="relative z-10 bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto"
      >
        <!-- Header -->
        <div class="flex items-center justify-between p-6 pb-0">
          <div>
            <h2 id="dialog-title" class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">
              {{ title }}
            </h2>
            <p v-if="description" id="dialog-description" class="mt-1 text-sm text-gray-500 dark:text-dark-text-tertiary">
              {{ description }}
            </p>
          </div>
          <button
            @click="emit('close')"
            aria-label="Close dialog"
            class="p-1 rounded-md text-gray-400 hover:text-gray-600 dark:hover:text-dark-text-secondary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <svg aria-hidden="true" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <!-- Body -->
        <div class="p-6">
          <slot />
        </div>

        <!-- Footer -->
        <div v-if="$slots.footer" class="px-6 pb-6 flex justify-end gap-3">
          <slot name="footer" />
        </div>
      </div>
    </div>
  </Teleport>
</template>
