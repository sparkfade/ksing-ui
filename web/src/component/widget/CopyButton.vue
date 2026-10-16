<template>
  <button class="copy" :class="{ sm: small }" :title="'复制'" @click.stop="copy">
    <svg v-if="!ok" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8">
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M5 15V5a2 2 0 0 1 2-2h10" />
    </svg>
    <svg v-else viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M4 12l5 5L20 7" />
    </svg>
    <span v-if="label">{{ ok ? '已复制' : label }}</span>
  </button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { toast } from '@/util/toast'

const props = withDefaults(defineProps<{ text: string; label?: string; small?: boolean }>(), {
  label: '',
})

const ok = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = props.text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
  ok.value = true
  if (!props.label) toast('已复制', 'success')
  setTimeout(() => (ok.value = false), 1500)
}
</script>

<style scoped>
.copy {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: 7px;
  border: 1px solid var(--c-border);
  background: transparent;
  color: var(--c-text-dim);
  font-size: 12.5px;
  font-family: var(--font);
  cursor: pointer;
  transition: all 0.15s var(--ease);
  white-space: nowrap;
}

.copy:hover {
  color: var(--c-primary);
  border-color: var(--c-primary);
  background: var(--c-primary-soft);
}

.copy.sm {
  padding: 2px 7px;
}
</style>
