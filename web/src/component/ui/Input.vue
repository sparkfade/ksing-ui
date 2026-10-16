<template>
  <label class="field" :class="{ wide: textarea }">
    <span v-if="label" class="label">
      {{ label }}
      <i v-if="hint" class="hint">{{ hint }}</i>
    </span>
    <textarea
      v-if="textarea"
      v-model="model"
      class="ctrl"
      :placeholder="placeholder"
      :rows="rows"
      :disabled="disabled"
    ></textarea>
    <input
      v-else
      v-model="model"
      class="ctrl"
      :type="type"
      :placeholder="placeholder"
      :disabled="disabled"
      :min="min"
      :max="max"
      autocomplete="off"
    />
  </label>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    label?: string
    hint?: string
    type?: string
    placeholder?: string
    textarea?: boolean
    rows?: number
    disabled?: boolean
    min?: number
    max?: number
  }>(),
  { type: 'text', placeholder: '', rows: 5 },
)

const model = defineModel<string | number>({ default: '' })
</script>

<style scoped>
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

.field.wide {
  grid-column: 1 / -1;
}

.label {
  font-size: 12.5px;
  color: var(--c-text-dim);
  font-weight: 500;
}

.hint {
  font-style: normal;
  margin-left: 6px;
  opacity: 0.75;
  font-weight: 400;
}

.ctrl {
  width: 100%;
  padding: 9px 12px;
  border-radius: 10px;
  border: 1px solid var(--c-border);
  background: var(--c-inset);
  color: var(--c-text);
  font-size: 13.5px;
  font-family: var(--font);
  outline: none;
  transition: border-color 0.15s var(--ease), box-shadow 0.15s var(--ease), background-color 0.2s var(--ease);
}

.ctrl::placeholder {
  color: var(--c-text-faint);
}

.ctrl:hover:not(:disabled) {
  border-color: var(--c-border-strong);
}

.ctrl:focus {
  border-color: var(--c-primary);
  box-shadow: 0 0 0 3px var(--c-primary-soft);
}

.ctrl:disabled {
  opacity: 0.5;
}

textarea.ctrl {
  resize: vertical;
  font-family: var(--mono);
  font-size: 12.5px;
  line-height: 1.6;
}
</style>
