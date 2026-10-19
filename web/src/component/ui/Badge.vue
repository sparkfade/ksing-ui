<template>
  <span class="badge" :class="color"><slot /></span>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{ color?: 'cyan' | 'green' | 'red' | 'yellow' | 'dim' | 'purple' }>(),
  { color: 'cyan' },
)
</script>

<style scoped>
.badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 10px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 500;
  border: 1px solid transparent;
  white-space: nowrap;
  line-height: 1.5;
}

.cyan {
  background: var(--c-primary-soft);
  color: var(--c-primary);
  border-color: var(--c-primary-bd);
}

.green {
  background: var(--c-green-soft);
  color: var(--c-green);
  border-color: var(--c-green-bd);
}

.red {
  background: var(--c-red-soft);
  color: var(--c-red);
  border-color: var(--c-red-bd);
}

.yellow {
  background: var(--c-yellow-soft);
  color: var(--c-yellow);
  border-color: var(--c-yellow-bd);
}

.dim {
  background: var(--c-dim-soft);
  color: var(--c-text-dim);
  border-color: var(--c-border);
}

.purple {
  background: var(--c-purple-soft);
  color: var(--c-purple);
  border-color: var(--c-purple-bd);
}
</style>
