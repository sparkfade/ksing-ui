<template>
  <button
    class="btn"
    :class="[variant, { sm: small, block }]"
    :type="type"
    :disabled="disabled || loading"
  >
    <span v-if="loading" class="mini-spin"></span>
    <slot />
  </button>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'primary' | 'default' | 'danger' | 'ghost'
    small?: boolean
    block?: boolean
    loading?: boolean
    disabled?: boolean
    type?: 'button' | 'submit'
  }>(),
  { variant: 'default', type: 'button' },
)
</script>

<style scoped>
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 7px 16px;
  border-radius: 6px;
  border: 1px solid var(--c-border);
  background: var(--c-card-2);
  color: var(--c-text);
  font-size: 13.5px;
  font-family: var(--font);
  cursor: pointer;
  transition: all 0.15s ease;
  white-space: nowrap;
}

.btn:hover:not(:disabled) {
  border-color: var(--c-primary);
  color: var(--c-primary);
  transform: translateY(-1px);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn.primary {
  background: var(--c-primary);
  border-color: var(--c-primary);
  color: var(--c-on-primary);
  font-weight: 600;
}

.btn.primary:hover:not(:disabled) {
  background: var(--c-primary-dark);
  border-color: var(--c-primary-dark);
  color: var(--c-on-primary);
  box-shadow: var(--shadow-btn);
}

.btn.danger {
  background: transparent;
  border-color: var(--c-red-bd);
  color: var(--c-red);
}

.btn.danger:hover:not(:disabled) {
  background: var(--c-red-soft);
  border-color: var(--c-red);
  color: var(--c-red);
}

.btn.ghost {
  background: transparent;
  border-color: transparent;
  color: var(--c-text-dim);
}

.btn.ghost:hover:not(:disabled) {
  color: var(--c-primary);
  background: var(--c-primary-soft);
}

.btn.sm {
  padding: 3px 10px;
  font-size: 12.5px;
}

.btn.block {
  width: 100%;
}

.mini-spin {
  width: 12px;
  height: 12px;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: spin 0.7s linear infinite;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
