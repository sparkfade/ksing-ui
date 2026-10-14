<template>
  <Teleport to="body">
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
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
  padding: 20px;
}

.modal {
  background: var(--c-card);
  border: 1px solid var(--c-border);
  border-radius: 12px;
  width: 480px;
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
}

.foot {
  padding: 12px 18px;
  border-top: 1px solid var(--c-border);
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
