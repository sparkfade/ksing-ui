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
  padding: 8px 16px;
  border-radius: 10px;
  border: 1px solid var(--c-border-strong);
  background: var(--c-card-2);
  color: var(--c-text);
  font-size: 13.5px;
  font-family: var(--font);
  cursor: pointer;
  transition: all 0.16s var(--ease);
  white-space: nowrap;
}

.btn:hover:not(:disabled) {
  border-color: var(--c-primary);
  color: var(--c-primary);
  transform: translateY(-1px);
}

.btn:active:not(:disabled) {
  transform: translateY(0);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn.primary {
  background: linear-gradient(180deg, var(--c-primary), var(--c-primary-strong));
  border-color: transparent;
  color: var(--c-on-primary);
  font-weight: 600;
  box-shadow: var(--shadow-btn);
}

.btn.primary:hover:not(:disabled) {
  filter: brightness(1.08);
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
  transform: none;
}

.btn.sm {
  padding: 4px 11px;
  font-size: 12.5px;
  border-radius: 8px;
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
