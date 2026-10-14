export type Theme = 'dark' | 'light'

const KEY = 'theme'

export function currentTheme(): Theme {
  const saved = localStorage.getItem(KEY)
  if (saved === 'dark' || saved === 'light') return saved
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

export function setTheme(t: Theme): Theme {
  localStorage.setItem(KEY, t)
  document.documentElement.dataset.theme = t
  return t
}

export function initTheme() {
  document.documentElement.dataset.theme = currentTheme()
}
