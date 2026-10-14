import { reactive } from 'vue'

export const confirmState = reactive({
  visible: false,
  text: '',
  resolve: null as ((ok: boolean) => void) | null,
})

export function confirmDialog(text: string): Promise<boolean> {
  return new Promise((resolve) => {
    confirmState.text = text
    confirmState.visible = true
    confirmState.resolve = resolve
  })
}

export function settleConfirm(ok: boolean) {
  confirmState.visible = false
  confirmState.resolve?.(ok)
  confirmState.resolve = null
}
