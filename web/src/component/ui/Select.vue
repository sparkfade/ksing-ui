<template>
  <label class="field">
    <span v-if="label" class="label">
      {{ label }}
      <i v-if="hint" class="hint">{{ hint }}</i>
    </span>
    <select v-model="model" class="ctrl" :disabled="disabled">
      <option v-for="o in normalized" :key="o.value" :value="o.value">{{ o.label }}</option>
    </select>
  </label>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    options: Array<string | { label: string; value: string }>
    label?: string
    hint?: string
    disabled?: boolean
  }>(),
  { label: '' },
)

const model = defineModel<string>({ default: '' })

const normalized = computed(() =>
  props.options.map((o) => (typeof o === 'string' ? { label: o, value: o } : o)),
)
</script>

<style scoped>
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

.label {
  font-size: 12.5px;
  color: var(--c-text-dim);
}

.hint {
  font-style: normal;
  margin-left: 6px;
  opacity: 0.75;
}

.ctrl {
  width: 100%;
  padding: 8px 11px;
  border-radius: 6px;
  border: 1px solid var(--c-border);
  background: var(--c-bg);
  color: var(--c-text);
  font-size: 13.5px;
  font-family: var(--font);
  outline: none;
  cursor: pointer;
}

.ctrl:focus {
  border-color: var(--c-primary);
}
</style>
