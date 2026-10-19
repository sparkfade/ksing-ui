<template>
  <Teleport to="body">
    <Transition name="draw">
      <div v-if="visible" class="overlay" @click.self="close">
        <div
          ref="box"
          class="drawer"
          :style="{ width }"
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

withDefaults(defineProps<{ title?: string; width?: string }>(), { title: '', width: '460px' })
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
  outline: none;
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 20px;
  border-bottom: 1px solid var(--c-border);
}

.head h3 {
  min-width: 0;
  margin: 0;
  font-size: 15.5px;
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
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
  flex-wrap: wrap;
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
