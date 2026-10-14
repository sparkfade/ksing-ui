<template>
  <div class="spin-wrap">
    <div class="spin" :style="{ width: size + 'px', height: size + 'px' }"></div>
    <span v-if="text" class="muted">{{ text }}</span>
  </div>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ size?: number; text?: string }>(), { size: 22, text: '加载中…' })
</script>

<style scoped>
.spin-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 30px 0;
}

.spin {
  border: 2px solid var(--c-border);
  border-top-color: var(--c-primary);
  border-radius: 50%;
  animation: rot 0.8s linear infinite;
}

@keyframes rot {
  to {
    transform: rotate(360deg);
  }
}
</style>
