<template>
  <div class="msel">
    <span v-if="label" class="label">{{ label }}<i v-if="hint" class="hint">{{ hint }}</i></span>
    <div class="box">
      <div v-if="model.length" class="chips">
        <span v-for="v in model" :key="v" class="chip">
          {{ labelOf(v) }}
          <b class="x" @click="toggle(v)">×</b>
        </span>
      </div>
      <div v-if="!opts.length" class="none muted">无可选项</div>
      <div v-else class="opts">
        <label v-for="o in opts" :key="o.value" class="opt">
          <input type="checkbox" :checked="model.includes(o.value)" @change="toggle(o.value)" />
          <span>{{ o.label }}</span>
        </label>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  options: Array<string | { label: string; value: string }>
  label?: string
  hint?: string
}>()

const model = defineModel<string[]>({ default: () => [] })

const opts = computed(() => props.options.map((o) => (typeof o === 'string' ? { label: o, value: o } : o)))

function labelOf(v: string): string {
  return opts.value.find((o) => o.value === v)?.label ?? v
}

function toggle(v: string) {
  const i = model.value.indexOf(v)
  if (i === -1) model.value = [...model.value, v]
  else model.value = model.value.filter((x) => x !== v)
}
</script>

<style scoped>
.msel {
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

.box {
  border: 1px solid var(--c-border);
  border-radius: 6px;
  background: var(--c-bg);
  padding: 6px;
}

.chips {
  padding: 2px 2px 6px;
  border-bottom: 1px dashed var(--c-border);
  margin-bottom: 4px;
}

.opts {
  max-height: 140px;
  overflow-y: auto;
}

.opt {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 8px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 13px;
}

.opt:hover {
  background: var(--c-primary-soft);
}

.opt input {
  accent-color: var(--c-primary);
}

.none {
  padding: 8px;
  font-size: 13px;
}
</style>
