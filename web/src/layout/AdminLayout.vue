<template>
  <div class="layout">
    <div v-if="menuOpen" class="mask" @click="menuOpen = false"></div>

    <aside class="side" :class="{ open: menuOpen }">
      <div class="logo">
        <svg viewBox="0 0 24 24" width="22" height="22">
          <path fill="var(--c-primary)" d="M13.6 3.5 5.5 13.6h5.2l-1.3 6.9 8.1-10.1h-5.2l1.3-6.9z" />
        </svg>
        <span>KSING-UI</span>
        <div class="spacer"></div>
        <ThemeToggle />
      </div>

      <nav class="nav">
        <router-link v-for="n in navs" :key="n.to" :to="n.to" class="nav-item" active-class="on">
          <span class="ico" v-html="n.icon"></span>
          {{ n.label }}
        </router-link>
      </nav>

      <div class="foot">
        <div class="me">
          <span class="avatar">{{ auth.name.slice(0, 1).toUpperCase() }}</span>
          <div class="me-txt">
            <b>{{ auth.name }}</b>
            <Badge color="cyan">管理员</Badge>
          </div>
        </div>
        <div class="srv-state" :title="srvTotal ? `${srvOnline}/${srvTotal} 节点在线` : '暂无服务器节点'">
          <span class="dot" :class="{ on: srvOnline > 0 }"></span>
          <span class="muted">{{ srvTotal ? `节点 ${srvOnline}/${srvTotal} 在线` : '暂无服务器节点' }}</span>
        </div>
        <Button block @click="doLogout">退出登录</Button>
      </div>
    </aside>

    <div class="main-wrap">
      <header class="topbar">
        <button class="burger" title="菜单" @click="menuOpen = !menuOpen">☰</button>
        <span class="tb-title">KSING-UI</span>
        <div class="spacer"></div>
        <ThemeToggle />
      </header>
      <main class="main">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import ThemeToggle from '@/component/widget/ThemeToggle.vue'
import { auth, logout } from '@/util/auth'
import { get } from '@/util/request'
import type { StatusData } from '@/types'

const router = useRouter()
const route = useRoute()
const srvOnline = ref(0)
const srvTotal = ref(0)
const menuOpen = ref(false)
let timer: ReturnType<typeof setInterval> | undefined

const navs = [
  { to: '/dashboard', label: '仪表盘', icon: '◈' },
  { to: '/servers', label: '服务器节点', icon: '⛁' },
  { to: '/certs', label: '证书', icon: '❖' },
  { to: '/nodes', label: '出站节点', icon: '⇄' },
  { to: '/users', label: '用户', icon: '♟' },
  { to: '/routes', label: '分流规则', icon: '⑂' },
  { to: '/rulesets', label: '规则集', icon: '☰' },
  { to: '/settings', label: '设置', icon: '⚙' },
]

watch(() => route.path, () => (menuOpen.value = false))

async function refreshStatus() {
  try {
    const s = await get<StatusData>('/api/status')
    srvOnline.value = s.counts.servers_online
    srvTotal.value = s.counts.servers
  } catch {
    /* 401 已由 request 处理 */
  }
}

function doLogout() {
  logout()
  router.replace('/login')
}

onMounted(() => {
  refreshStatus()
  timer = setInterval(refreshStatus, 20000)
})

onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.layout {
  display: flex;
  min-height: 100vh;
}

.side {
  width: 216px;
  flex-shrink: 0;
  background: var(--c-card);
  border-right: 1px solid var(--c-border);
  display: flex;
  flex-direction: column;
  position: sticky;
  top: 0;
  height: 100vh;
  z-index: 60;
  transition: background-color 0.2s ease, border-color 0.2s ease, transform 0.2s ease;
}

.logo {
  display: flex;
  align-items: center;
  gap: 9px;
  padding: 18px 16px 16px;
  font-size: 17px;
  font-weight: 700;
  letter-spacing: 1px;
  color: var(--c-text);
  border-bottom: 1px solid var(--c-border);
}

.nav {
  flex: 1;
  padding: 12px 10px;
  display: flex;
  flex-direction: column;
  gap: 3px;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-radius: 8px;
  color: var(--c-text-dim);
  font-size: 13.5px;
  transition: all 0.15s ease;
}

.nav-item .ico {
  width: 18px;
  text-align: center;
  font-size: 14px;
}

.nav-item:hover {
  color: var(--c-text);
  background: var(--c-hover);
}

.nav-item.on {
  color: var(--c-primary);
  background: var(--c-primary-soft);
}

.foot {
  padding: 14px;
  border-top: 1px solid var(--c-border);
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.me {
  display: flex;
  align-items: center;
  gap: 10px;
}

.avatar {
  width: 34px;
  height: 34px;
  border-radius: 50%;
  background: var(--c-primary-soft);
  color: var(--c-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  flex-shrink: 0;
}

.me-txt {
  display: flex;
  flex-direction: column;
  gap: 3px;
  align-items: flex-start;
  min-width: 0;
}

.me-txt b {
  font-size: 13.5px;
  max-width: 110px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.srv-state {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
}

.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--c-text-dim);
  flex-shrink: 0;
}

.dot.on {
  background: var(--c-green);
  box-shadow: 0 0 6px var(--c-green);
}

.main-wrap {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.topbar {
  display: none;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
  background: var(--c-card);
  border-bottom: 1px solid var(--c-border);
  position: sticky;
  top: 0;
  z-index: 50;
}

.burger {
  width: 32px;
  height: 32px;
  border-radius: 8px;
  border: 1px solid var(--c-border);
  background: transparent;
  color: var(--c-text);
  font-size: 16px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.tb-title {
  font-weight: 700;
  letter-spacing: 1px;
  font-size: 15px;
}

.main {
  flex: 1;
  min-width: 0;
  padding: 22px 26px 40px;
}

.mask {
  display: none;
}

@media (max-width: 767px) {
  .topbar {
    display: flex;
  }

  .side {
    position: fixed;
    left: 0;
    top: 0;
    bottom: 0;
    height: 100vh;
    transform: translateX(-105%);
    box-shadow: var(--shadow-pop);
  }

  .side.open {
    transform: none;
  }

  .mask {
    display: block;
    position: fixed;
    inset: 0;
    background: var(--c-overlay);
    z-index: 55;
  }

  .main {
    padding: 16px 14px 40px;
  }
}
</style>
