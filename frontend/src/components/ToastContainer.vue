<script setup lang="ts">
import { useToastStore } from "@/stores/toast";

const toastStore = useToastStore();

const styles: Record<string, string> = {
  success:
    "bg-green-50 border-green-200 text-green-800 dark:bg-green-900/20 dark:border-green-800/40 dark:text-green-300",
  error:
    "bg-red-50 border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800/40 dark:text-red-300",
  warning:
    "bg-amber-50 border-amber-200 text-amber-800 dark:bg-amber-900/20 dark:border-amber-800/40 dark:text-amber-300",
  info: "bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-900/20 dark:border-blue-800/40 dark:text-blue-300",
};
</script>

<template>
  <div
    class="fixed top-4 right-4 z-[100] flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)] pointer-events-none"
    aria-live="polite"
    aria-atomic="false"
  >
    <TransitionGroup name="toast">
      <div
        v-for="t in toastStore.toasts"
        :key="t.id"
        :class="styles[t.kind]"
        class="pointer-events-auto flex items-start gap-2 rounded-lg border shadow-sm px-3 py-2 text-sm"
        :role="t.kind === 'error' ? 'alert' : 'status'"
      >
        <span class="flex-1 break-words">{{ t.message }}</span>
        <button
          type="button"
          class="flex-shrink-0 opacity-60 hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-current rounded"
          aria-label="Dismiss notification"
          @click="toastStore.dismiss(t.id)"
        >
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.2s ease;
}
.toast-enter-from {
  opacity: 0;
  transform: translateX(1rem);
}
.toast-leave-to {
  opacity: 0;
  transform: translateX(1rem);
}
</style>
