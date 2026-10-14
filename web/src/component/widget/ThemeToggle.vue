<template>
  <button
    class="theme-btn"
    :title="theme === 'dark' ? '切换为亮色主题' : '切换为暗色主题'"
    @click="toggle"
  >
    {{ theme === 'dark' ? '☀' : '☾' }}
  </button>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { currentTheme, setTheme, type Theme } from '@/util/theme'

const theme = ref<Theme>(currentTheme())

function toggle() {
  theme.value = setTheme(theme.value === 'dark' ? 'light' : 'dark')
}
</script>

<style scoped>
.theme-btn {
  width: 30px;
  height: 30px;
  border-radius: 8px;
  border: 1px solid var(--c-border);
  background: transparent;
  color: var(--c-text-dim);
  font-size: 14px;
  line-height: 1;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s ease;
  flex-shrink: 0;
}

.theme-btn:hover {
  color: var(--c-primary);
  border-color: var(--c-primary);
}
</style>
