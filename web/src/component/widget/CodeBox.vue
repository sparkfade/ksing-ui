<template>
  <div class="code-box">
    <span class="txt" :class="{ multi }">{{ text }}</span>
    <CopyButton :text="text" small />
  </div>
</template>

<script setup lang="ts">
import CopyButton from './CopyButton.vue'

defineProps<{ text: string; multiline?: boolean }>()
</script>

<style scoped>
.code-box {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--c-inset);
  border: 1px solid var(--c-border);
  border-radius: 10px;
  padding: 9px 12px;
}

.txt {
  flex: 1;
  font-family: var(--mono);
  font-size: 12.5px;
  color: var(--c-text);
  word-break: break-all;
  line-height: 1.6;
  max-height: 72px;
  overflow-y: auto;
}

.txt.multi {
  white-space: pre-wrap;
  max-height: 56vh;
}
</style>
