<template>
  <div>
    <div class="page-head">
      <h2>证书</h2>
      <div class="spacer"></div>
      <Button small @click="load" :loading="loading">刷新</Button>
    </div>

    <p class="muted" style="margin: -6px 0 14px; font-size: 12.5px">
      证书由节点上的 sing-box 自动申请与续签 (Let's Encrypt ACME)；域名证书需在添加节点时绑定域名。
    </p>

    <div class="card">
      <Spinner v-if="loading && !certs.length" />
      <Empty v-else-if="!certs.length" text="暂无服务器节点，请先在「服务器节点」添加" />
      <div v-else class="table-wrap">
        <table class="tbl">
          <thead>
            <tr>
              <th>节点</th>
              <th>域名</th>
              <th>证书模式</th>
              <th>签发者</th>
              <th>过期时间</th>
              <th>剩余天数</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in certs" :key="c.sid">
              <td>
                <span class="dot" :class="{ on: c.online }"></span>
                <span style="font-weight: 600">{{ c.name }}</span>
                <div class="mono muted sid">{{ c.sid }}</div>
              </td>
              <td class="mono">{{ c.domain || 'IP 模式' }}</td>
              <td><Badge :color="modeColor(c.cert_mode)">{{ modeLabel(c.cert_mode) }}</Badge></td>
              <td class="muted">{{ c.issuer || '-' }}</td>
              <td class="mono">{{ c.not_after ? fmtTime(c.not_after) : '-' }}</td>
              <td><Badge :color="statusColor(c.status)">{{ statusText(c) }}</Badge></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Empty from '@/component/ui/Empty.vue'
import Spinner from '@/component/ui/Spinner.vue'
import { get } from '@/util/request'
import { toast } from '@/util/toast'
import { fmtTime } from '@/util/format'
import type { CertItem } from '@/types'

const certs = ref<CertItem[]>([])
const loading = ref(true)
let timer: ReturnType<typeof setInterval> | undefined

function modeLabel(m: CertItem['cert_mode']): string {
  return { acme: '域名证书', selfip: 'IP 自签', unsafe: '不安全' }[m || 'selfip']
}

function modeColor(m: CertItem['cert_mode']): 'green' | 'yellow' | 'red' {
  return { acme: 'green', selfip: 'yellow', unsafe: 'red' }[m || 'selfip'] as 'green' | 'yellow' | 'red'
}

function statusColor(s: CertItem['status']): 'green' | 'yellow' | 'red' | 'dim' {
  return { ok: 'green', expiring: 'yellow', expired: 'red', pending: 'dim' }[s] as 'green' | 'yellow' | 'red' | 'dim'
}

function statusText(c: CertItem): string {
  if (c.status === 'pending') return '申请中/未上报'
  if (c.status === 'expired') return '已过期'
  return `剩 ${Math.round(c.days_left ?? 0)} 天`
}

async function load() {
  loading.value = true
  try {
    certs.value = await get<CertItem[]>('/api/certs')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  timer = setInterval(load, 30000)
})

onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.sid {
  font-size: 11.5px;
  margin-top: 3px;
}

.dot {
  display: inline-block;
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--c-text-dim);
  margin-right: 7px;
}

.dot.on {
  background: var(--c-green);
  box-shadow: 0 0 5px var(--c-green);
}
</style>
