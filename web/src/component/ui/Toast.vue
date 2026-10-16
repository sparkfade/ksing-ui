<template>
  <Teleport to="body">
    <div class="toast-host">
      <TransitionGroup name="t">
        <div v-for="t in toastList" :key="t.id" class="toast" :class="t.type">
          {{ t.text }}
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { toastList } from '@/util/toast'
</script>

<style scoped>
.toast-host {
  position: fixed;
  top: 18px;
  left: 50%;
  transform: translateX(-50%);
  z-index: 200;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  pointer-events: none;
}

.toast {
  padding: 10px 20px;
  border-radius: 10px;
  font-size: 13.5px;
  background: var(--c-card-2);
  border: 1px solid var(--c-border-strong);
  color: var(--c-text);
  box-shadow: var(--shadow-pop);
  max-width: 70vw;
}

.toast.success {
  border-color: var(--c-green-bd);
  color: var(--c-green);
}

.toast.error {
  border-color: var(--c-red-bd);
  color: var(--c-red);
}

.toast.info {
  border-color: var(--c-primary-bd);
  color: var(--c-primary);
}

.t-enter-active,
.t-leave-active {
  transition: all 0.25s var(--ease);
}

.t-enter-from,
.t-leave-to {
  opacity: 0;
  transform: translateY(-10px);
}
</style>
