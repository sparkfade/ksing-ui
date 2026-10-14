<template>
  <Teleport to="body">
    <div v-if="visible" class="overlay" @click.self="close">
      <div class="drawer" :style="{ width }">
        <div class="head">
          <h3>{{ title }}</h3>
          <button class="x" @click="close">×</button>
        </div>
        <div class="body">
          <slot />
        </div>
        <div v-if="$slots.footer" class="foot">
          <slot name="footer" />
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ title?: string; width?: string }>(), { title: '', width: '440px' })
const visible = defineModel<boolean>('visible', { required: true })

function close() {
  visible.value = false
}
</script>

<style scoped>
.overlay {
  position: fixed;
  inset: 0;
  background: var(--c-overlay);
  z-index: 100;
}

.drawer {
  position: absolute;
  top: 0;
  right: 0;
  height: 100%;
  max-width: 94vw;
  background: var(--c-card);
  border-left: 1px solid var(--c-border);
  display: flex;
  flex-direction: column;
  box-shadow: var(--shadow-pop);
  animation: slide-in 0.18s ease;
}

@keyframes slide-in {
  from {
    transform: translateX(40px);
    opacity: 0;
  }
  to {
    transform: translateX(0);
    opacity: 1;
  }
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  border-bottom: 1px solid var(--c-border);
}

.head h3 {
  margin: 0;
  font-size: 15px;
}

.x {
  background: none;
  border: none;
  color: var(--c-text-dim);
  font-size: 20px;
  cursor: pointer;
  line-height: 1;
  padding: 2px 6px;
  border-radius: 4px;
}

.x:hover {
  color: var(--c-text);
  background: var(--c-hover-2);
}

.body {
  padding: 16px 18px;
  overflow-y: auto;
  flex: 1;
}

.foot {
  padding: 12px 18px;
  border-top: 1px solid var(--c-border);
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
