<template>
  <Teleport to="body">
    <Transition name="pop">
      <div v-if="confirmState.visible" class="overlay" @click.self="settleConfirm(false)">
        <div
          ref="box"
          class="box"
          role="dialog"
          aria-modal="true"
          aria-label="确认操作"
          tabindex="-1"
        >
          <p class="msg">{{ confirmState.text }}</p>
          <div class="acts">
            <Button @click="settleConfirm(false)">取消</Button>
            <Button variant="danger" @click="settleConfirm(true)">确认</Button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { nextTick, onUnmounted, ref, watch } from 'vue'
import Button from './Button.vue'
import { confirmState, settleConfirm } from '@/util/confirm'

const box = ref<HTMLElement>()
let prevFocus: HTMLElement | null = null

function onKey(e: KeyboardEvent) {
  if (e.key !== 'Escape') return
  e.stopPropagation()
  settleConfirm(false)
}

watch(
  () => confirmState.visible,
  async (v) => {
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
  },
)

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
  z-index: 150;
  padding: 20px;
}

.box {
  background: var(--c-card);
  border: 1px solid var(--c-border-strong);
  border-radius: var(--r-lg);
  width: 400px;
  max-width: 100%;
  padding: 22px 22px 16px;
  box-shadow: var(--shadow-pop);
  outline: none;
}

.msg {
  margin: 0 0 18px;
  font-size: 14px;
  line-height: 1.6;
  white-space: pre-line;
  word-break: break-all;
}

.acts {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}

.pop-enter-active,
.pop-leave-active {
  transition: opacity 0.16s var(--ease);
}

.pop-enter-active .box,
.pop-leave-active .box {
  transition: transform 0.16s var(--ease);
}

.pop-enter-from,
.pop-leave-to {
  opacity: 0;
}

.pop-enter-from .box {
  transform: scale(0.96);
}
</style>
