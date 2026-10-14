<template>
  <router-view />
  <Toast />
  <ConfirmDialog />
</template>

<script setup lang="ts">
import { provide } from 'vue'
import Toast from '@/component/ui/Toast.vue'
import ConfirmDialog from '@/component/ui/ConfirmDialog.vue'
import { toast } from '@/util/toast'

provide('toast', toast)
</script>
