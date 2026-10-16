<template>
  <div class="page">
    <div class="page-head">
      <h2>仪表盘</h2>
      <div class="spacer"></div>
      <Button small @click="loadAll" :loading="loading">刷新</Button>
    </div>
    <p class="page-sub">配置变更实时（秒级）自动下发到各服务器节点并生效，无需手动应用。</p>

    <Spinner v-if="loading && !st" />

    <template v-else-if="st">
      <!-- 概览统计 -->
      <div class="stat-grid">
        <div class="card stat">
          <span class="stat-label">在线节点</span>
          <span class="stat-num">
            {{ st.counts.servers_online }}<small class="muted stat-sub"> / {{ st.counts.servers }}</small>
          </span>
          <span class="stat-foot muted">服务器节点</span>
        </div>
        <div class="card stat">
          <span class="stat-label">用户数</span>
          <span class="stat-num">{{ st.counts.users }}</span>
          <span class="stat-foot muted">规则 {{ st.counts.rules }} · 规则集 {{ st.counts.rulesets }}</span>
        </div>
        <div class="card stat">
          <span class="stat-label">总流量</span>
          <span class="stat-num">{{ fmtBytes(totalUp + totalDown) }}</span>
          <span class="stat-foot muted">↑ {{ fmtBytes(totalUp) }} · ↓ {{ fmtBytes(totalDown) }}</span>
        </div>
        <div class="card stat">
          <span class="stat-label">实时速率<span class="live-dot" title="每 2 秒刷新"></span></span>
          <span class="stat-num rate">
            <b class="arr up">↑</b>{{ fmtBytes(rates?.total.rate_up) }}/s
          </span>
          <span class="stat-foot muted">
            <b class="arr down">↓</b> {{ fmtBytes(rates?.total.rate_down) }}/s
          </span>
        </div>
      </div>

      <div class="grid2">
        <!-- 节点列表 -->
        <div class="card">
          <h3 class="card-title">
            节点列表
            <span class="sub">{{ servers.length }} 个</span>
            <div class="spacer"></div>
            <router-link to="/servers" class="more">管理 →</router-link>
          </h3>
          <Empty v-if="!servers.length" text="暂无服务器节点">
            <Button small variant="primary" @click="router.push('/servers')">去添加</Button>
          </Empty>
          <div v-else class="srv-list">
            <div v-for="s in servers" :key="s.sid" class="srv-row" @click="router.push('/servers')">
              <span class="dot" :class="{ on: s.online }"></span>
              <div class="srv-main">
                <div class="srv-line1">
                  <span class="srv-name">{{ s.name }}</span>
                  <Badge v-if="s.sb_running === true" color="green">核心运行中</Badge>
                  <Badge v-else-if="s.sb_running === false" color="red">核心停止</Badge>
                  <Badge :color="s.synced ? 'green' : 'yellow'">{{ s.synced ? '已同步' : '待同步' }}</Badge>
                </div>
                <div class="srv-line2 mono muted">
                  {{ s.cert_mode === 'acme' ? s.domain : s.reported_ip || '待上报' }}:{{ s.port }}
                </div>
              </div>
              <div class="srv-nums">
                <span class="mono srv-rate">
                  <b class="arr up">↑</b>{{ fmtBytes(rateOf(s.sid)?.rate_up) }}/s
                  <b class="arr down">↓</b>{{ fmtBytes(rateOf(s.sid)?.rate_down) }}/s
                </span>
                <span class="mono muted">累计 {{ fmtBytes((s.traffic?.up || 0) + (s.traffic?.down || 0)) }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- 系统状态 -->
        <div class="card">
          <h3 class="card-title">系统状态<span class="sub">面板主机</span></h3>
          <template v-if="sys">
            <div class="sys-row">
              <span class="sys-label">CPU</span>
              <div class="meter"><i :class="lvlClass(sys.cpu)" :style="{ width: clampPct(sys.cpu) + '%' }"></i></div>
              <span class="sys-val mono">{{ sys.cpu.toFixed(0) }}%</span>
            </div>
            <div class="sys-row">
              <span class="sys-label">内存</span>
              <div class="meter"><i :class="lvlClass(sys.mem.percent)" :style="{ width: clampPct(sys.mem.percent) + '%' }"></i></div>
              <span class="sys-val mono">{{ fmtBytes(sys.mem.used) }}/{{ fmtBytes(sys.mem.total) }}</span>
            </div>
            <div class="sys-row">
              <span class="sys-label">磁盘</span>
              <div class="meter"><i :class="lvlClass(sys.disk.percent)" :style="{ width: clampPct(sys.disk.percent) + '%' }"></i></div>
              <span class="sys-val mono">{{ fmtBytes(sys.disk.used) }}/{{ fmtBytes(sys.disk.total) }}</span>
            </div>
            <div class="sys-foot muted">
              负载 {{ sys.load.map((n) => n.toFixed(2)).join(' · ') }}　|　运行时间 {{ fmtUptime(sys.uptime) }}
            </div>
          </template>
          <Empty v-else text="加载中…" />
        </div>
      </div>

      <!-- 流量排名 -->
      <div class="card">
        <h3 class="card-title">流量排名<span class="sub">用户 Top10</span></h3>
        <Empty v-if="!userRank.length" text="暂无流量数据" />
        <div v-else class="rank-grid">
          <div v-for="r in userRank" :key="r.name" class="rank-row">
            <span class="rank-name" :title="r.name">{{ r.name }}</span>
            <div class="meter"><i :style="{ width: r.pct + '%' }"></i></div>
            <span class="mono rank-val">{{ fmtBytes(r.total) }}</span>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Empty from '@/component/ui/Empty.vue'
import Spinner from '@/component/ui/Spinner.vue'
import { get } from '@/util/request'
import { toast } from '@/util/toast'
import { fmtBytes } from '@/util/format'
import type { RateStat, ServerItem, StatusData, SystemInfo, TrafficData } from '@/types'

const router = useRouter()
const st = ref<StatusData>()
const servers = ref<ServerItem[]>([])
const traffic = ref<TrafficData>({ users: {}, servers: {} })
const sys = ref<SystemInfo>()
const loading = ref(false)
let fastTimer: ReturnType<typeof setInterval> | undefined
let slowTimer: ReturnType<typeof setInterval> | undefined

const rates = computed(() => traffic.value.rates)
const totalUp = computed(() => Object.values(traffic.value.users).reduce((a, t) => a + (t?.up || 0), 0))
const totalDown = computed(() => Object.values(traffic.value.users).reduce((a, t) => a + (t?.down || 0), 0))

function rateOf(sid: string): RateStat | undefined {
  return traffic.value.rates?.servers?.[sid]
}

const userRank = computed(() => {
  const arr = Object.entries(traffic.value.users)
    .map(([name, t]) => ({ name, total: (t?.up || 0) + (t?.down || 0) }))
    .filter((x) => x.total > 0)
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
  const max = arr[0]?.total || 1
  return arr.map((x) => ({ ...x, pct: Math.max(3, Math.round((x.total / max) * 100)) }))
})

async function loadAll() {
  loading.value = true
  try {
    const [s, sv, tf] = await Promise.all([
      get<StatusData>('/api/status'),
      get<ServerItem[]>('/api/servers'),
      get<TrafficData>('/api/traffic'),
    ])
    st.value = s
    servers.value = sv
    traffic.value = tf
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

async function pollFast() {
  if (document.hidden) return
  try {
    const [tf, si] = await Promise.all([get<TrafficData>('/api/traffic'), get<SystemInfo>('/api/system')])
    traffic.value = tf
    sys.value = si
  } catch {
    /* 轮询失败静默，401 已由 request 处理 */
  }
}

async function pollSlow() {
  if (document.hidden) return
  try {
    const [s, sv] = await Promise.all([get<StatusData>('/api/status'), get<ServerItem[]>('/api/servers')])
    st.value = s
    servers.value = sv
  } catch {
    /* 同上 */
  }
}

function clampPct(n: number): number {
  return Math.min(100, Math.max(0, n || 0))
}

function lvlClass(pct: number): string {
  if (pct > 85) return 'r'
  if (pct >= 60) return 'y'
  return 'g'
}

function fmtUptime(sec: number): string {
  if (!sec) return '-'
  const d = Math.floor(sec / 86400)
  const h = Math.floor((sec % 86400) / 3600)
  const m = Math.floor((sec % 3600) / 60)
  if (d > 0) return `${d} 天 ${h} 小时`
  if (h > 0) return `${h} 小时 ${m} 分钟`
  return `${m} 分钟`
}

onMounted(() => {
  loadAll()
  pollFast()
  fastTimer = setInterval(pollFast, 2000)
  slowTimer = setInterval(pollSlow, 20000)
})

onUnmounted(() => {
  clearInterval(fastTimer)
  clearInterval(slowTimer)
})
</script>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 14px;
  margin-bottom: 16px;
}

.stat {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 16px 18px;
}

.stat-label {
  font-size: 12.5px;
  color: var(--c-text-dim);
  display: flex;
  align-items: center;
  gap: 7px;
}

.stat-num {
  font-size: 25px;
  font-weight: 700;
  line-height: 1.25;
  font-variant-numeric: tabular-nums;
}

.stat-num.rate {
  font-size: 21px;
}

.stat-sub {
  font-size: 14px;
  font-weight: 400;
}

.stat-foot {
  font-size: 12px;
}

.live-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--c-green);
  box-shadow: 0 0 6px var(--c-green);
  animation: pulse 1.6s ease-in-out infinite;
}

@keyframes pulse {
  50% {
    opacity: 0.3;
  }
}

.arr {
  font-weight: 700;
}

.arr.up {
  color: var(--c-green);
}

.arr.down {
  color: var(--c-primary);
}

.grid2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}

.more {
  font-size: 12.5px;
  font-weight: 400;
}

.srv-list {
  display: flex;
  flex-direction: column;
}

.srv-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 10px;
  border-radius: 10px;
  border-bottom: 1px dashed var(--c-border);
  cursor: pointer;
  transition: background-color 0.12s var(--ease);
}

.srv-row:last-child {
  border-bottom: none;
}

.srv-row:hover {
  background: var(--c-hover);
}

.srv-main {
  min-width: 0;
  flex: 1;
}

.srv-line1 {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.srv-name {
  font-weight: 600;
  font-size: 13.5px;
}

.srv-line2 {
  font-size: 11.5px;
  margin-top: 2px;
}

.srv-nums {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 2px;
  flex-shrink: 0;
}

.srv-rate {
  font-size: 12px;
}

.sys-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 0;
}

.sys-label {
  width: 36px;
  flex-shrink: 0;
  font-size: 13px;
  color: var(--c-text-dim);
}

.sys-row .meter {
  flex: 1;
}

.sys-val {
  width: 118px;
  text-align: right;
  flex-shrink: 0;
  font-size: 12px;
}

.sys-foot {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed var(--c-border);
  font-size: 12.5px;
}

.rank-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 4px 24px;
}

.rank-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 5px 0;
}

.rank-name {
  width: 110px;
  flex-shrink: 0;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.rank-row .meter {
  flex: 1;
}

.rank-val {
  width: 76px;
  text-align: right;
  flex-shrink: 0;
  font-size: 12px;
}

@media (max-width: 767px) {
  .grid2 {
    grid-template-columns: 1fr;
  }

  .srv-nums {
    align-items: flex-end;
  }
}
</style>
