<template>
  <div class="qr">
    <canvas ref="el"></canvas>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import QRCode from 'qrcode'

const props = withDefaults(defineProps<{ text: string; size?: number }>(), { size: 168 })

const el = ref<HTMLCanvasElement>()

async function render() {
  if (!el.value || !props.text) return
  try {
    await QRCode.toCanvas(el.value, props.text, {
      width: props.size,
      margin: 1,
      color: { dark: '#0f1115', light: '#ffffff' },
    })
  } catch {
    /* 文本过长等异常忽略 */
  }
}

onMounted(render)
watch(() => props.text, render)
</script>

<style scoped>
.qr {
  display: inline-flex;
  padding: 8px;
  background: #fff;
  border-radius: 8px;
  line-height: 0;
}
</style>
