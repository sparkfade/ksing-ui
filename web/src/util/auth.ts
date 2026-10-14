import { reactive } from 'vue'

export const auth = reactive({
  token: localStorage.getItem('token') || '',
  role: localStorage.getItem('role') || '',
  name: localStorage.getItem('name') || '',
})

export function login(token: string, role: string, name: string) {
  auth.token = token
  auth.role = role
  auth.name = name
  localStorage.setItem('token', token)
  localStorage.setItem('role', role)
  localStorage.setItem('name', name)
}

export function logout() {
  auth.token = ''
  auth.role = ''
  auth.name = ''
  localStorage.removeItem('token')
  localStorage.removeItem('role')
  localStorage.removeItem('name')
}
