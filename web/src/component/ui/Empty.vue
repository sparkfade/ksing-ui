<template>
  <div class="empty">
    <svg viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="currentColor" stroke-width="1.5">
      <path d="M3 8l3-4h12l3 4v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8z" />
      <path d="M3 8h18M10 12h4" />
    </svg>
    <p>{{ text }}</p>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ text?: string }>(), { text: '暂无数据' })
</script>

<style scoped>
.empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  padding: 36px 0;
  color: var(--c-text-dim);
}

p {
  margin: 0;
  font-size: 13px;
}
</style>
