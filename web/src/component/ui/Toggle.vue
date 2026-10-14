<template>
  <label class="toggle" :class="{ on: model, disabled }">
    <input type="checkbox" v-model="model" :disabled="disabled" />
    <span class="track"><span class="thumb"></span></span>
    <span v-if="label" class="txt">{{ label }}</span>
  </label>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ label?: string; disabled?: boolean }>(), { label: '' })
const model = defineModel<boolean>({ default: false })
</script>

<style scoped>
.toggle {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  user-select: none;
}

.toggle.disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

input {
  display: none;
}

.track {
  width: 36px;
  height: 20px;
  border-radius: 20px;
  background: var(--c-border);
  position: relative;
  transition: background 0.2s ease;
  flex-shrink: 0;
}

.thumb {
  position: absolute;
  top: 2px;
  left: 2px;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--c-text-dim);
  transition: all 0.2s ease;
}

.toggle.on .track {
  background: var(--c-primary);
}

.toggle.on .thumb {
  left: 18px;
  background: var(--c-on-primary);
}

.txt {
  font-size: 13px;
}
</style>
