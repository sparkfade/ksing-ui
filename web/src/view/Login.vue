<template>
  <div class="login-page">
    <div class="theme-corner"><ThemeToggle /></div>

    <div class="card login-card">
      <div class="logo">
        <svg viewBox="0 0 24 24" width="34" height="34">
          <path fill="var(--c-primary)" d="M13.6 3.5 5.5 13.6h5.2l-1.3 6.9 8.1-10.1h-5.2l1.3-6.9z" />
        </svg>
        <h1>ksing-ui</h1>
      </div>
      <p class="sub muted">{{ setup ? '首次使用：初始化管理员账号' : 'sing-box 中控面板' }}</p>

      <Spinner v-if="loading" :size="18" text="连接服务器…" />

      <form v-else @submit.prevent="submit" class="form">
        <Input v-model="username" label="用户名" placeholder="请输入用户名" />
        <Input v-model="password" label="密码" type="password" placeholder="请输入密码" />
        <Input
          v-if="setup"
          v-model="confirmPwd"
          label="确认密码"
          type="password"
          placeholder="再次输入密码"
        />
        <p v-if="error" class="err">{{ error }}</p>
        <Button variant="primary" block type="submit" :loading="submitting">
          {{ setup ? '初始化并登录' : '登 录' }}
        </Button>
      </form>

      <p v-if="meta" class="ver muted">面板 v{{ meta.version }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import Button from '@/component/ui/Button.vue'
import Input from '@/component/ui/Input.vue'
import Spinner from '@/component/ui/Spinner.vue'
import ThemeToggle from '@/component/widget/ThemeToggle.vue'
import { get, post } from '@/util/request'
import { login } from '@/util/auth'

interface Meta {
  name: string
  version: string
  setup_needed: boolean
}

const router = useRouter()
const loading = ref(true)
const setup = ref(false)
const meta = ref<Meta>()
const username = ref('')
const password = ref('')
const confirmPwd = ref('')
const error = ref('')
const submitting = ref(false)

onMounted(async () => {
  try {
    const m = await get<Meta>('/api/meta')
    meta.value = m
    setup.value = m.setup_needed
  } catch {
    error.value = '无法连接服务器'
  } finally {
    loading.value = false
  }
})

async function submit() {
  error.value = ''
  if (!username.value || !password.value) {
    error.value = '请输入用户名和密码'
    return
  }
  if (setup.value && password.value !== confirmPwd.value) {
    error.value = '两次输入的密码不一致'
    return
  }
  submitting.value = true
  try {
    const url = setup.value ? '/api/setup' : '/api/login'
    const res = await post<{ token: string; role: string; name: string }>(url, {
      username: username.value,
      password: password.value,
    })
    login(res.token, res.role, res.name)
    router.replace(res.role === 'admin' ? '/' : '/my')
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background:
    radial-gradient(640px 320px at 20% 0%, var(--c-glow), transparent),
    radial-gradient(520px 280px at 85% 100%, var(--c-glow), transparent),
    var(--c-bg);
}

.theme-corner {
  position: fixed;
  top: 16px;
  right: 16px;
  z-index: 5;
}

.login-card {
  width: min(380px, 100%);
  padding: 36px 32px 26px;
  box-shadow: var(--shadow-pop);
  animation: page-in 0.3s var(--ease);
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
}

.logo h1 {
  margin: 0;
  font-size: 23px;
  letter-spacing: 1.5px;
}

.sub {
  text-align: center;
  margin: 8px 0 26px;
  font-size: 13px;
}

.form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.err {
  margin: 0;
  color: var(--c-red);
  font-size: 13px;
}

.ver {
  text-align: center;
  font-size: 12px;
  margin: 24px 0 0;
}
</style>
