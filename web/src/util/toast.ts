import { reactive } from 'vue'

export interface ToastItem {
  id: number
  type: 'success' | 'error' | 'info'
  text: string
}

export const toastList = reactive<ToastItem[]>([])

let seq = 0

export function toast(text: string, type: ToastItem['type'] = 'info') {
  const id = ++seq
  toastList.push({ id, type, text })
  setTimeout(() => {
    const i = toastList.findIndex((t) => t.id === id)
    if (i !== -1) toastList.splice(i, 1)
  }, 3500)
}
