<script setup lang="ts">
interface Props {
  open: boolean;
  title: string;
  message: string;
  entityName?: string;
  isLoading: boolean;
  isDangerous?: boolean;
  confirmLabel?: string;
}

withDefaults(defineProps<Props>(), {
  isDangerous: true,
  confirmLabel: "Delete",
  entityName: "",
});

const emit = defineEmits<{
  close: [];
  confirm: [];
}>();
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="fixed inset-0 z-50 flex items-center justify-center"
    >
      <div class="absolute inset-0 bg-black/50" @click="emit('close')" />
      <div
        class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-md mx-4 border border-gray-200 dark:border-dark-border"
      >
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
          <h3
            class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
          >
            {{ title }}
          </h3>
        </div>
        <div class="p-6">
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
            {{ message }}
            <span v-if="entityName" class="font-semibold">{{
              entityName
            }}</span>
          </p>
        </div>
        <div
          class="px-6 py-4 border-t border-gray-200 dark:border-dark-border flex justify-end gap-3"
        >
          <button
            @click="emit('close')"
            class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
          >
            Cancel
          </button>
          <button
            @click="emit('confirm')"
            :disabled="isLoading"
            class="px-4 py-2 text-white rounded-md disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            :class="
              isDangerous
                ? 'bg-red-600 hover:bg-red-700'
                : 'bg-primary-600 hover:bg-primary-700'
            "
          >
            {{ isLoading ? "Deleting..." : confirmLabel }}
          </button>
        </div>
      </div>
    </div>
  </Teleport>
</template>
