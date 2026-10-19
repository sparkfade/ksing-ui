<template>
  <div class="page dashboard-page">
    <div class="page-head">
      <div class="title-block">
        <span class="page-kicker">OVERVIEW</span>
        <h2>仪表盘</h2>
      </div>
      <div class="spacer"></div>
      <Button small @click="loadAll" :loading="loading">刷新</Button>
      <Button small variant="primary" @click="router.push('/servers')">管理节点</Button>
    </div>
    <p class="page-sub">节点状态、实时上下行速率与流量累计集中展示；配置保存后由节点自动拉取生效。</p>

    <Spinner v-if="loading && !st" />

    <template v-else-if="st">
      <div class="statusbar">
        <span class="state-pill">
          <span class="live-dot" aria-hidden="true"></span>
          面板在线
        </span>
        <span class="status-item"><b>{{ st.counts.servers_online }}</b> / {{ st.counts.servers }} 节点在线</span>
        <span class="status-item">{{ st.counts.users }} 用户 · {{ st.counts.rules }} 规则</span>
        <span class="spacer"></span>
        <span class="status-item muted">每 2 秒采样 · {{ lastUpdatedText }}</span>
      </div>

      <div class="vitals">
        <article class="card vital">
          <div class="vital-head">
            <span class="vital-icon">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <rect x="4" y="4" width="16" height="6" rx="2" />
                <rect x="4" y="14" width="16" height="6" rx="2" />
                <path d="M8 7h.01M8 17h.01" />
              </svg>
            </span>
            <span>在线节点</span>
          </div>
          <div class="vital-value">
            {{ st.counts.servers_online }}<span class="vital-unit">/ {{ st.counts.servers }}</span>
          </div>
          <div class="vital-foot">
            <span class="inline-status">
              <span class="dot" :class="{ on: st.counts.servers_online > 0 }" aria-hidden="true"></span>
              {{ st.counts.servers_online > 0 ? '节点链路正常' : '等待节点上线' }}
            </span>
          </div>
        </article>

        <article class="card vital">
          <div class="vital-head">
            <span class="vital-icon">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="9" cy="8" r="3" />
                <path d="M3.5 19c.4-3.3 2.2-5 5.5-5s5.1 1.7 5.5 5" />
                <path d="M16 5.5a3 3 0 0 1 0 5.5M17.5 14c2 .5 3 2.2 3.2 5" />
              </svg>
            </span>
            <span>用户</span>
          </div>
          <div class="vital-value">{{ st.counts.users }}</div>
          <div class="vital-foot">规则 {{ st.counts.rules }} · 规则集 {{ st.counts.rulesets }}</div>
        </article>

        <article class="card vital">
          <div class="vital-head">
            <span class="vital-icon">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M7 17V7m0 0-3 3m3-3 3 3M17 7v10m0 0-3-3m3 3 3-3" />
              </svg>
            </span>
            <span>累计流量</span>
          </div>
          <div class="vital-value">
            {{ totalParts.value }}<span class="vital-unit">{{ totalParts.unit }}</span>
          </div>
          <div class="vital-foot split">
            <span class="up">↑ {{ fmtBytes(totalUp) }}</span>
            <span class="down">↓ {{ fmtBytes(totalDown) }}</span>
          </div>
        </article>

        <article class="card vital">
          <div class="vital-head">
            <span class="vital-icon">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M3 12h4l2.2-5 4.2 10 2.4-5H21" />
              </svg>
            </span>
            <span>实时总速率</span>
          </div>
          <div class="vital-value">
            {{ totalRateParts.value }}<span class="vital-unit">{{ totalRateParts.unit }}/s</span>
          </div>
          <div class="vital-foot split">
            <span class="up"><i>↑</i> {{ fmtRate(rates?.total.rate_up) }}</span>
            <span class="down"><i>↓</i> {{ fmtRate(rates?.total.rate_down) }}</span>
          </div>
        </article>
      </div>

      <div class="dash-grid top-grid">
        <section class="card throughput-card">
          <div class="wide-head">
            <div>
              <div class="section-kicker">实时吞吐</div>
              <div class="wide-sub">近 60 秒采样趋势 · 峰值 {{ fmtRate(trendPeak) }}</div>
            </div>
            <div class="wide-legend">
              <span class="legend-item up">
                <i class="legend-line" aria-hidden="true"></i>
                上行
                <b>{{ fmtRate(rates?.total.rate_up) }}</b>
              </span>
              <span class="legend-item down">
                <i class="legend-line" aria-hidden="true"></i>
                下行
                <b>{{ fmtRate(rates?.total.rate_down) }}</b>
              </span>
            </div>
          </div>

          <div class="chart-box">
            <svg
              class="trend-chart"
              :viewBox="`0 0 ${CHART_W} ${CHART_H}`"
              preserveAspectRatio="none"
              role="img"
              aria-label="最近一分钟上行和下行速率趋势"
            >
              <defs>
                <linearGradient id="up-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="var(--c-green)" stop-opacity="0.28" />
                  <stop offset="100%" stop-color="var(--c-green)" stop-opacity="0" />
                </linearGradient>
                <linearGradient id="down-fill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="var(--c-primary)" stop-opacity="0.2" />
                  <stop offset="100%" stop-color="var(--c-primary)" stop-opacity="0" />
                </linearGradient>
              </defs>
              <line v-for="y in [0, 60, 120, 180]" :key="y" x1="0" :y1="y" :x2="CHART_W" :y2="y" class="grid-line" />
              <path :d="downSeries.area" fill="url(#down-fill)" />
              <path :d="upSeries.area" fill="url(#up-fill)" />
              <path :d="downSeries.line" class="series-line down-line" />
              <path :d="upSeries.line" class="series-line up-line" />
            </svg>
            <div v-if="trendHistory.length < 2" class="chart-empty">正在采集速率样本…</div>
          </div>

          <div class="wide-foot">
            <div>
              <span>累计上行</span>
              <b class="up">{{ fmtBytes(totalUp) }}</b>
            </div>
            <div>
              <span>累计下行</span>
              <b class="down">{{ fmtBytes(totalDown) }}</b>
            </div>
            <div>
              <span>当前合计</span>
              <b>{{ fmtBytes((rates?.total.rate_up || 0) + (rates?.total.rate_down || 0)) }}/s</b>
            </div>
          </div>
        </section>

        <section class="card system-card">
          <div class="section-head">
            <div>
              <div class="section-kicker">系统状态</div>
              <div class="wide-sub">面板主机</div>
            </div>
          </div>
          <template v-if="sys">
            <div class="system-row">
              <div class="system-line">
                <span>CPU</span>
                <b class="mono">{{ sys.cpu.toFixed(1) }}%</b>
              </div>
              <div class="meter"><i :class="lvlClass(sys.cpu)" :style="{ width: clampPct(sys.cpu) + '%' }"></i></div>
            </div>
            <div class="system-row">
              <div class="system-line">
                <span>内存</span>
                <b class="mono">{{ fmtBytes(sys.mem.used) }} / {{ fmtBytes(sys.mem.total) }}</b>
              </div>
              <div class="meter"><i :class="lvlClass(sys.mem.percent)" :style="{ width: clampPct(sys.mem.percent) + '%' }"></i></div>
            </div>
            <div class="system-row">
              <div class="system-line">
                <span>磁盘</span>
                <b class="mono">{{ fmtBytes(sys.disk.used) }} / {{ fmtBytes(sys.disk.total) }}</b>
              </div>
              <div class="meter"><i :class="lvlClass(sys.disk.percent)" :style="{ width: clampPct(sys.disk.percent) + '%' }"></i></div>
            </div>
            <div class="system-foot">
              <span>负载 {{ sys.load.map((n) => n.toFixed(2)).join(' · ') || '-' }}</span>
              <span>运行 {{ fmtUptime(sys.uptime) }}</span>
            </div>
          </template>
          <Empty v-else text="加载中…" />
        </section>
      </div>

      <div class="dash-grid bottom-grid">
        <section class="card">
          <h3 class="card-title">
            节点流量
            <span class="sub">{{ servers.length }} 个节点</span>
            <div class="spacer"></div>
            <router-link to="/servers" class="more">管理 →</router-link>
          </h3>
          <Empty v-if="!servers.length" text="暂无服务器节点">
            <Button small variant="primary" @click="router.push('/servers')">去添加</Button>
          </Empty>
          <div v-else class="node-list">
            <article
              v-for="s in servers"
              :key="s.sid"
              class="node-row"
              role="button"
              tabindex="0"
              @click="router.push('/servers')"
              @keydown.enter="router.push('/servers')"
            >
              <div class="node-main">
                <div class="node-line1">
                  <span class="node-name">{{ s.name }}</span>
                  <span class="node-state" :class="{ on: s.online }">
                    <span class="dot" :class="{ on: s.online }" aria-hidden="true"></span>
                    {{ s.online ? '在线' : '离线' }}
                  </span>
                  <Badge v-if="s.sb_running === true" color="green">核心运行中</Badge>
                  <Badge v-else-if="s.sb_running === false" color="red">核心停止</Badge>
                  <Badge :color="s.synced ? 'green' : 'yellow'">{{ s.synced ? '已同步' : '待同步' }}</Badge>
                </div>
                <div class="node-address mono muted">{{ srvAddr(s) }}</div>
                <div v-if="v6Warn(s)" class="node-warning" :title="v6Warn(s)">
                  <span aria-hidden="true">⚠</span>
                  <span>{{ v6Warn(s) }}</span>
                </div>
                <div class="node-share" :title="`占累计流量 ${nodeShare(s)}%`">
                  <i :style="{ width: nodeShare(s) + '%' }"></i>
                </div>
              </div>
              <div class="node-metrics">
                <div class="node-metric">
                  <span class="metric-label up"><i>↑</i> 上行速率</span>
                  <span class="metric-value mono">{{ fmtRate(rateOf(s.sid)?.rate_up) }}</span>
                </div>
                <div class="node-metric">
                  <span class="metric-label down"><i>↓</i> 下行速率</span>
                  <span class="metric-value mono">{{ fmtRate(rateOf(s.sid)?.rate_down) }}</span>
                </div>
                <div class="node-metric">
                  <span class="metric-label"><i class="up">↑</i> 累计上行</span>
                  <span class="metric-value mono">{{ fmtBytes(s.traffic?.up) }}</span>
                </div>
                <div class="node-metric">
                  <span class="metric-label"><i class="down">↓</i> 累计下行</span>
                  <span class="metric-value mono">{{ fmtBytes(s.traffic?.down) }}</span>
                </div>
              </div>
            </article>
          </div>
        </section>

        <section class="card">
          <h3 class="card-title">
            用户流量
            <span class="sub">Top 10</span>
          </h3>
          <Empty v-if="!userRank.length" text="暂无流量数据" />
          <div v-else class="rank-list">
            <div v-for="(r, idx) in userRank" :key="r.name" class="rank-row">
              <div class="rank-head">
                <span class="rank-index mono">{{ String(idx + 1).padStart(2, '0') }}</span>
                <span class="rank-name" :title="r.name">{{ r.name }}</span>
                <span class="rank-total mono">{{ fmtBytes(r.total) }}</span>
              </div>
              <div class="meter"><i :style="{ width: r.pct + '%' }"></i></div>
              <div class="rank-meta">
                <span class="up">↑ {{ fmtBytes(r.up) }}</span>
                <span class="down">↓ {{ fmtBytes(r.down) }}</span>
              </div>
            </div>
          </div>
        </section>
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
import { fmtBytes, fmtBytesParts } from '@/util/format'
import type { RateStat, ServerItem, StatusData, SystemInfo, TrafficData } from '@/types'

interface TrendPoint {
  up: number
  down: number
  at: number
}

interface ChartSeries {
  line: string
  area: string
}

const router = useRouter()
const st = ref<StatusData>()
const servers = ref<ServerItem[]>([])
const traffic = ref<TrafficData>({ users: {}, servers: {} })
const sys = ref<SystemInfo>()
const loading = ref(false)
const trendHistory = ref<TrendPoint[]>([])
const lastUpdated = ref(0)
let fastTimer: ReturnType<typeof setInterval> | undefined
let slowTimer: ReturnType<typeof setInterval> | undefined

const CHART_W = 720
const CHART_H = 180
const TREND_SAMPLES = 30

const rates = computed(() => traffic.value.rates)
const totalUp = computed(() => Object.values(traffic.value.users).reduce((a, t) => a + (t?.up || 0), 0))
const totalDown = computed(() => Object.values(traffic.value.users).reduce((a, t) => a + (t?.down || 0), 0))
const totalParts = computed(() => fmtBytesParts(totalUp.value + totalDown.value))
const totalRateParts = computed(() => fmtBytesParts(
  (rates.value?.total.rate_up || 0) + (rates.value?.total.rate_down || 0),
))
const trendPeak = computed(() => Math.max(
  0,
  ...trendHistory.value.flatMap((p) => [p.up, p.down]),
))
const lastUpdatedText = computed(() => {
  if (!lastUpdated.value) return '等待采样'
  return `更新于 ${new Date(lastUpdated.value).toLocaleTimeString('zh-CN', { hour12: false })}`
})

const downSeries = computed<ChartSeries>(() => buildSeries('down'))
const upSeries = computed<ChartSeries>(() => buildSeries('up'))

const userRank = computed(() => {
  const arr = Object.entries(traffic.value.users)
    .map(([name, t]) => ({
      name,
      up: t?.up || 0,
      down: t?.down || 0,
      total: (t?.up || 0) + (t?.down || 0),
    }))
    .filter((x) => x.total > 0)
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
  const max = arr[0]?.total || 1
  return arr.map((x) => ({ ...x, pct: Math.max(3, Math.round((x.total / max) * 100)) }))
})

function buildSeries(key: 'up' | 'down'): ChartSeries {
  const data = trendHistory.value
  if (data.length < 2) return { line: '', area: '' }
  const max = Math.max(1, trendPeak.value)
  const x = (i: number) => (i / (data.length - 1)) * CHART_W
  const y = (value: number) => CHART_H - 4 - (Math.max(0, value) / max) * (CHART_H - 14)
  const points = data.map((p, i) => `${x(i).toFixed(2)} ${y(p[key]).toFixed(2)}`)
  const line = `M ${points[0]} L ${points.slice(1).join(' L ')}`
  const area = `M 0 ${CHART_H} L ${points.join(' L ')} L ${CHART_W} ${CHART_H} Z`
  return { line, area }
}

function recordTraffic(tf: TrafficData) {
  traffic.value = tf
  const up = Math.max(0, Number(tf.rates?.total.rate_up) || 0)
  const down = Math.max(0, Number(tf.rates?.total.rate_down) || 0)
  trendHistory.value = [
    ...trendHistory.value.slice(-(TREND_SAMPLES - 1)),
    { up, down, at: Date.now() },
  ]
  lastUpdated.value = Date.now()
}

function fmtRate(n?: number): string {
  return `${fmtBytes(n)}/s`
}

function rateOf(sid: string): RateStat | undefined {
  return traffic.value.rates?.servers?.[sid]
}

function srvAddr(s: ServerItem): string {
  const status = s.ip_status
  const wrap = (a: string) => (a.includes(':') ? `[${a}]` : a)
  const parts: string[] = []
  if (status) {
    if (status.ipv4.active && status.ipv4.address) parts.push(`${wrap(status.ipv4.address)}:${s.port}`)
    if (status.ipv6.active && status.ipv6.address) parts.push(`${wrap(status.ipv6.address)}:${s.port}`)
  }
  if (parts.length) return parts.join(' / ')
  const fallback = s.cert_mode === 'acme' ? s.domain || s.domain6 : s.reported_ipv4 || s.reported_ipv6 || s.reported_ip
  return fallback ? `${wrap(fallback)}:${s.port}` : '待上报'
}

function v6Warn(s: ServerItem): string {
  const v6 = s.ip_status?.ipv6
  if (v6 && v6.enabled && !v6.active && v6.reported_ip && v6.error) return v6.error
  return ''
}

function nodeShare(s: ServerItem): number {
  const used = (s.traffic?.up || 0) + (s.traffic?.down || 0)
  const total = totalUp.value + totalDown.value
  if (!used || !total) return 0
  return Math.max(1, Math.min(100, Math.round((used / total) * 100)))
}

async function loadAll() {
  loading.value = true
  try {
    const [status, serverList, trafficData, systemInfo] = await Promise.all([
      get<StatusData>('/api/status'),
      get<ServerItem[]>('/api/servers'),
      get<TrafficData>('/api/traffic'),
      get<SystemInfo>('/api/system'),
    ])
    st.value = status
    servers.value = serverList
    sys.value = systemInfo
    recordTraffic(trafficData)
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

let fastBusy = false
async function pollFast() {
  if (document.hidden || fastBusy) return
  fastBusy = true
  try {
    const [trafficData, systemInfo] = await Promise.all([
      get<TrafficData>('/api/traffic'),
      get<SystemInfo>('/api/system'),
    ])
    sys.value = systemInfo
    recordTraffic(trafficData)
  } catch {
    /* 轮询失败静默，401 已由 request 处理 */
  } finally {
    fastBusy = false
  }
}

let slowBusy = false
async function pollSlow() {
  if (document.hidden || slowBusy) return
  slowBusy = true
  try {
    const [status, serverList] = await Promise.all([
      get<StatusData>('/api/status'),
      get<ServerItem[]>('/api/servers'),
    ])
    st.value = status
    servers.value = serverList
  } catch {
    /* 同上 */
  } finally {
    slowBusy = false
  }
}

function clampPct(n: number): number {
  return Math.min(100, Math.max(0, n || 0))
}

function lvlClass(percent: number): string {
  if (percent > 85) return 'r'
  if (percent >= 60) return 'y'
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
  fastTimer = setInterval(pollFast, 2000)
  slowTimer = setInterval(pollSlow, 20000)
})

onUnmounted(() => {
  clearInterval(fastTimer)
  clearInterval(slowTimer)
})
</script>

<style scoped>
.dashboard-page {
  --dash-gap: 14px;
  --dash-pad: 20px;
}

.title-block {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.page-kicker,
.section-kicker {
  font-size: 10.5px;
  font-weight: 600;
  letter-spacing: 0.12em;
  color: var(--c-text-faint);
}

.title-block h2 {
  line-height: 1.2;
}

.statusbar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 16px;
  min-height: 44px;
  padding: 7px 14px;
  margin-bottom: var(--dash-gap);
  border: 1px solid var(--c-border);
  border-radius: 999px;
  background: var(--c-card);
  box-shadow: var(--shadow-card);
  font-size: 12.5px;
}

.state-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding-right: 4px;
  font-weight: 600;
}

.status-item {
  position: relative;
  white-space: nowrap;
}

.status-item + .status-item::before {
  content: '';
  display: inline-block;
  width: 1px;
  height: 12px;
  margin-right: 16px;
  vertical-align: -2px;
  background: var(--c-border);
}

.live-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--c-green);
  box-shadow: 0 0 0 3px var(--c-green-soft);
  animation: live-pulse 1.8s ease-in-out infinite;
}

@keyframes live-pulse {
  50% {
    opacity: 0.45;
  }
}

.vitals {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--dash-gap);
  margin-bottom: var(--dash-gap);
}

.vitals > .card,
.dash-grid > .card {
  margin-top: 0;
}

.vital {
  position: relative;
  overflow: hidden;
  padding: 16px var(--dash-pad) 15px;
}

.vital::after {
  content: '';
  position: absolute;
  inset: auto 18px 0;
  height: 2px;
  border-radius: 2px 2px 0 0;
  background: linear-gradient(90deg, transparent, var(--c-primary-bd), transparent);
  opacity: 0.7;
}

.vital-head {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--c-text-dim);
  font-size: 12px;
  font-weight: 500;
}

.vital-icon {
  display: inline-flex;
  width: 28px;
  height: 28px;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: var(--c-primary-soft);
  color: var(--c-primary);
}

.vital-icon svg {
  width: 16px;
  height: 16px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.vital-value {
  display: flex;
  align-items: baseline;
  gap: 4px;
  margin-top: 14px;
  font-size: 30px;
  font-weight: 700;
  line-height: 1;
  letter-spacing: -0.02em;
  font-variant-numeric: tabular-nums;
}

.vital-unit {
  font-size: 13px;
  font-weight: 500;
  letter-spacing: 0;
  color: var(--c-text-dim);
}

.vital-foot {
  margin-top: 12px;
  color: var(--c-text-faint);
  font-size: 11.5px;
}

.vital-foot.split {
  display: flex;
  justify-content: space-between;
  gap: 8px;
}

.inline-status {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}

.up {
  color: var(--c-green);
}

.down {
  color: var(--c-primary);
}

.dash-grid {
  display: grid;
  grid-template-columns: minmax(0, 2fr) minmax(280px, 1fr);
  gap: var(--dash-gap);
  margin-bottom: var(--dash-gap);
}

.throughput-card {
  padding-bottom: 0;
}

.wide-head,
.section-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}

.wide-sub {
  margin-top: 4px;
  color: var(--c-text-faint);
  font-size: 12px;
}

.wide-legend {
  display: flex;
  align-items: center;
  gap: 18px;
  flex-wrap: wrap;
}

.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  color: var(--c-text-dim);
  font-size: 11.5px;
}

.legend-item b {
  color: var(--c-text);
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}

.legend-line {
  width: 14px;
  height: 2px;
  border-radius: 2px;
  background: currentColor;
}

.chart-box {
  position: relative;
  height: 190px;
  margin: 12px -6px 0;
}

.trend-chart {
  display: block;
  width: 100%;
  height: 100%;
  overflow: visible;
}

.grid-line {
  stroke: var(--c-border);
  stroke-width: 1;
  stroke-dasharray: 2 5;
  vector-effect: non-scaling-stroke;
}

.series-line {
  fill: none;
  stroke-width: 1.8;
  stroke-linecap: round;
  stroke-linejoin: round;
  vector-effect: non-scaling-stroke;
}

.up-line {
  stroke: var(--c-green);
}

.down-line {
  stroke: var(--c-primary);
}

.chart-empty {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--c-text-faint);
  font-size: 12px;
}

.wide-foot {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin: 8px 0 0;
  padding: 14px 0 16px;
  border-top: 1px solid var(--c-border);
}

.wide-foot > div {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}

.wide-foot span {
  color: var(--c-text-faint);
  font-size: 10.5px;
  letter-spacing: 0.05em;
}

.wide-foot b {
  font-size: 16px;
  font-variant-numeric: tabular-nums;
}

.system-card {
  display: flex;
  flex-direction: column;
}

.system-row {
  margin-top: 17px;
}

.system-line {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 7px;
  color: var(--c-text-dim);
  font-size: 12.5px;
}

.system-line b {
  color: var(--c-text);
  font-size: 11.5px;
  font-weight: 500;
}

.system-foot {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  margin-top: auto;
  padding-top: 16px;
  color: var(--c-text-faint);
  font-size: 11.5px;
}

.more {
  font-size: 12.5px;
  font-weight: 400;
}

.node-list {
  display: flex;
  flex-direction: column;
}

.node-row {
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 12px 8px;
  border-bottom: 1px dashed var(--c-border);
  border-radius: 10px;
  cursor: pointer;
  transition: background-color 0.12s var(--ease);
}

.node-row:first-child {
  padding-top: 4px;
}

.node-row:last-child {
  padding-bottom: 2px;
  border-bottom: none;
}

.node-row:hover {
  background: var(--c-hover);
}

.node-main {
  flex: 1;
  min-width: 0;
}

.node-line1 {
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
}

.node-name {
  font-size: 13.5px;
  font-weight: 600;
}

.node-state {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 11.5px;
  color: var(--c-text-faint);
}

.node-state.on {
  color: var(--c-green);
}

.node-address {
  margin-top: 4px;
  font-size: 11.5px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}

.node-warning {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  margin-top: 4px;
  color: var(--c-yellow);
  font-size: 11.5px;
}

.node-share {
  height: 2px;
  margin-top: 9px;
  border-radius: 2px;
  background: var(--c-card-2);
  overflow: hidden;
}

.node-share i {
  display: block;
  height: 100%;
  border-radius: 2px;
  background: linear-gradient(90deg, var(--c-primary), var(--c-green));
  transition: width 0.35s var(--ease);
}

.node-metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(82px, 1fr));
  gap: 8px 14px;
  width: min(430px, 47%);
  flex-shrink: 0;
}

.node-metric {
  min-width: 0;
}

.metric-label {
  display: flex;
  align-items: center;
  gap: 4px;
  color: var(--c-text-faint);
  font-size: 10.5px;
  white-space: nowrap;
}

.metric-label i {
  font-style: normal;
  font-weight: 700;
}

.metric-value {
  display: block;
  margin-top: 3px;
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
}

.rank-list {
  display: flex;
  flex-direction: column;
  gap: 13px;
}

.rank-row {
  min-width: 0;
}

.rank-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 6px;
}

.rank-index {
  width: 20px;
  flex-shrink: 0;
  color: var(--c-text-faint);
  font-size: 10.5px;
}

.rank-name {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12.5px;
}

.rank-total {
  flex-shrink: 0;
  font-size: 11.5px;
}

.rank-meta {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  margin-top: 4px;
  font-size: 10.5px;
  font-variant-numeric: tabular-nums;
}

@media (max-width: 1100px) {
  .vitals {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .dash-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .node-metrics {
    width: min(420px, 50%);
  }
}

@media (max-width: 780px) {
  .dashboard-page {
    --dash-gap: 12px;
    --dash-pad: 16px;
  }

  .status-item + .status-item::before {
    display: none;
  }

  .node-row {
    align-items: flex-start;
    flex-direction: column;
    gap: 10px;
  }

  .node-metrics {
    width: 100%;
  }
}

@media (max-width: 560px) {
  .vitals {
    grid-template-columns: minmax(0, 1fr);
  }

  .statusbar {
    border-radius: var(--r-md);
  }

  .chart-box {
    height: 145px;
  }

  .wide-foot {
    grid-template-columns: minmax(0, 1fr);
  }

  .node-metrics {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (prefers-reduced-motion: reduce) {
  .live-dot {
    animation: none;
  }
}
</style>
