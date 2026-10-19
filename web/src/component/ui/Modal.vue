<template>
  <Teleport to="body">
    <Transition name="pop">
      <div v-if="visible" class="overlay" @click.self="close">
        <div
          ref="box"
          class="modal"
          role="dialog"
          aria-modal="true"
          :aria-label="title || '对话框'"
          tabindex="-1"
        >
          <div class="head">
            <h3>{{ title }}</h3>
            <button class="x" aria-label="关闭" @click="close">×</button>
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
import { nextTick, onUnmounted, ref, watch } from 'vue'
import { confirmState } from '@/util/confirm'

withDefaults(defineProps<{ title?: string }>(), { title: '' })
const visible = defineModel<boolean>('visible', { required: true })

const box = ref<HTMLElement>()
let prevFocus: HTMLElement | null = null

function close() {
  visible.value = false
}

function onKey(e: KeyboardEvent) {
  if (e.key !== 'Escape') return
  if (confirmState.visible) return // 确认框优先，避免连带关闭
  e.stopPropagation()
  close()
}

watch(visible, async (v) => {
  if (v) {
    prevFocus = document.activeElement as HTMLElement | null
    document.addEventListener('keydown', onKey)
    await nextTick()
    box.value?.focus()
  } else {
    document.removeEventListener('keydown', onKey)
    prevFocus?.focus?.()
    prevFocus = null
  }
})

onUnmounted(() => document.removeEventListener('keydown', onKey))
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
  outline: none;
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
