<template>
  <div class="ulayout">
    <header class="topbar">
      <div class="logo">
        <svg viewBox="0 0 24 24" width="20" height="20">
          <path fill="var(--c-primary)" d="M13.6 3.5 5.5 13.6h5.2l-1.3 6.9 8.1-10.1h-5.2l1.3-6.9z" />
        </svg>
        <span>KSING-UI</span>
      </div>
      <div class="spacer"></div>
      <ThemeToggle />
      <span class="uname">{{ auth.name }}</span>
      <Button small @click="doLogout">退出登录</Button>
    </header>

    <main class="umain">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import Button from '@/component/ui/Button.vue'
import ThemeToggle from '@/component/widget/ThemeToggle.vue'
import { auth, logout } from '@/util/auth'

const router = useRouter()

function doLogout() {
  logout()
  router.replace('/login')
}
</script>

<style scoped>
.ulayout {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.topbar {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 12px 22px;
  background: var(--c-card);
  border-bottom: 1px solid var(--c-border);
  position: sticky;
  top: 0;
  z-index: 10;
  transition: background-color 0.2s ease, border-color 0.2s ease;
}

.logo {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 16px;
  font-weight: 700;
  letter-spacing: 1px;
}

.spacer {
  flex: 1;
}

.uname {
  color: var(--c-text-dim);
  font-size: 13.5px;
}

.umain {
  flex: 1;
  width: 100%;
  max-width: 760px;
  margin: 0 auto;
  padding: 24px 18px 48px;
}

@media (max-width: 767px) {
  .topbar {
    padding: 10px 14px;
  }

  .uname {
    display: none;
  }

  .umain {
    padding: 16px 12px 48px;
  }
}
</style>
