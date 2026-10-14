import router from '@/router'

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function call<T>(method: string, url: string, body?: unknown): Promise<T> {
  const token = localStorage.getItem('token')
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = await res.json().catch(() => ({} as Record<string, string>))

  if (res.status === 401) {
    localStorage.removeItem('token')
    if (router.currentRoute.value.path !== '/login') router.replace('/login')
    throw new ApiError(401, data.error || '登录已过期')
  }
  if (!res.ok) throw new ApiError(res.status, data.error || `请求失败 (${res.status})`)
  return data as T
}

export const get = <T = unknown>(url: string) => call<T>('GET', url)
export const post = <T = unknown>(url: string, body?: unknown) => call<T>('POST', url, body)
export const put = <T = unknown>(url: string, body?: unknown) => call<T>('PUT', url, body)
export const del = <T = unknown>(url: string, body?: unknown) => call<T>('DELETE', url, body)
