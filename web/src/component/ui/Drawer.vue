<template>
  <Teleport to="body">
    <Transition name="draw">
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
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ title?: string; width?: string }>(), { title: '', width: '460px' })
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
  backdrop-filter: blur(3px);
  z-index: 100;
}

.drawer {
  position: absolute;
  top: 0;
  right: 0;
  height: 100%;
  max-width: 96vw;
  background: var(--c-card);
  border-left: 1px solid var(--c-border-strong);
  display: flex;
  flex-direction: column;
  box-shadow: var(--shadow-pop);
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid var(--c-border);
}

.head h3 {
  margin: 0;
  font-size: 15.5px;
  font-weight: 600;
}

.x {
  background: none;
  border: none;
  color: var(--c-text-dim);
  font-size: 20px;
  cursor: pointer;
  line-height: 1;
  padding: 4px 8px;
  border-radius: 8px;
  transition: all 0.15s var(--ease);
}

.x:hover {
  color: var(--c-text);
  background: var(--c-hover-2);
}

.body {
  padding: 18px 20px;
  overflow-y: auto;
  flex: 1;
}

.foot {
  padding: 14px 20px;
  border-top: 1px solid var(--c-border);
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.draw-enter-active,
.draw-leave-active {
  transition: opacity 0.2s var(--ease);
}

.draw-enter-active .drawer,
.draw-leave-active .drawer {
  transition: transform 0.22s var(--ease);
}

.draw-enter-from,
.draw-leave-to {
  opacity: 0;
}

.draw-enter-from .drawer,
.draw-leave-to .drawer {
  transform: translateX(48px);
}
</style>
