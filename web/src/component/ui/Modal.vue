<template>
  <Teleport to="body">
    <Transition name="pop">
      <div v-if="visible" class="overlay" @click.self="close">
        <div class="modal">
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
withDefaults(defineProps<{ title?: string }>(), { title: '' })
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
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: 20px;
}

.modal {
  background: var(--c-card);
  border: 1px solid var(--c-border-strong);
  border-radius: var(--r-lg);
  width: 520px;
  max-width: 100%;
  max-height: 85vh;
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
}

.foot {
  padding: 14px 20px;
  border-top: 1px solid var(--c-border);
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.pop-enter-active,
.pop-leave-active {
  transition: opacity 0.18s var(--ease);
}

.pop-enter-active .modal,
.pop-leave-active .modal {
  transition: transform 0.18s var(--ease), opacity 0.18s var(--ease);
}

.pop-enter-from,
.pop-leave-to {
  opacity: 0;
}

.pop-enter-from .modal {
  transform: translateY(14px) scale(0.98);
}

.pop-leave-to .modal {
  transform: translateY(8px) scale(0.98);
}
</style>
