<template>
  <div class="page">
    <div class="page-head">
      <h2>证书</h2>
      <div class="spacer"></div>
      <Button small @click="load" :loading="loading">刷新</Button>
    </div>
    <p class="page-sub">证书由节点上的 sing-box 自动申请与续签 (Let's Encrypt ACME)；域名证书需在添加节点时绑定域名。</p>

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
                <div class="mono faint sid">{{ c.sid }}</div>
              </td>
              <td>
                <div class="cert-fam">
                  <span class="mono">{{ c.domain || (c.cert_mode === 'acme' ? '未配置 IPv4 域名' : 'IP 模式') }}</span>
                  <span v-if="c.cert_mode === 'acme' && c.ip_status?.ipv4.enabled" class="rr" :class="rrCls(c.ip_status.ipv4)" :title="c.ip_status.ipv4.active ? 'A 记录正常' : c.ip_status.ipv4.error || '等待检测'">A</span>
                </div>
                <div v-if="c.domain6 || c.ip_status?.ipv6.enabled" class="cert-fam">
                  <span class="mono">{{ c.domain6 || '未配置 IPv6 域名' }}</span>
                  <span
                    v-if="c.cert_mode === 'acme' && c.ip_status?.ipv6.enabled"
                    class="rr"
                    :class="rrCls(c.ip_status.ipv6)"
                    :title="c.ip_status.ipv6.active ? 'AAAA 记录正常' : `${c.ip_status.ipv6.error || '等待检测'}；未就绪前暂不加入证书申请`"
                  >AAAA</span>
                </div>
              </td>
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
import type { CertItem, FamilyStatus } from '@/types'

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

function rrCls(f: FamilyStatus): string {
  return f.active ? 'ok' : 'warn'
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
  timer = setInterval(() => {
    if (!document.hidden) load()
  }, 30000)
})

onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.sid {
  font-size: 11.5px;
  margin-top: 3px;
}

.cert-fam {
  display: flex;
  align-items: center;
}

.cert-fam + .cert-fam {
  margin-top: 3px;
}

.rr {
  font-size: 10.5px;
  font-weight: 700;
  padding: 0 5px;
  border-radius: 4px;
  margin-left: 6px;
  line-height: 1.7;
}

.rr.ok {
  background: var(--c-green-soft);
  color: var(--c-green);
}

.rr.warn {
  background: var(--c-yellow-soft);
  color: var(--c-yellow);
  cursor: help;
}
</style>
