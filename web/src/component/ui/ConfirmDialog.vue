<template>
  <Teleport to="body">
    <div v-if="confirmState.visible" class="overlay" @click.self="settleConfirm(false)">
      <div class="box">
        <p class="msg">{{ confirmState.text }}</p>
        <div class="acts">
          <Button @click="settleConfirm(false)">取消</Button>
          <Button variant="danger" @click="settleConfirm(true)">确认</Button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import Button from './Button.vue'
import { confirmState, settleConfirm } from '@/util/confirm'
</script>

<style scoped>
.overlay {
  position: fixed;
  inset: 0;
  background: var(--c-overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 150;
  padding: 20px;
}

.box {
  background: var(--c-card);
  border: 1px solid var(--c-border);
  border-radius: 12px;
  width: 380px;
  max-width: 100%;
  padding: 22px 20px 16px;
  box-shadow: var(--shadow-pop);
}

.msg {
  margin: 0 0 18px;
  font-size: 14px;
  white-space: pre-line;
  word-break: break-all;
}

.acts {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}
</style>
