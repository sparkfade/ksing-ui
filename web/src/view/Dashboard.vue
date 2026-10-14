<template>
  <div>
    <div class="page-head">
      <h2>仪表盘</h2>
      <div class="spacer"></div>
      <Button small @click="loadAll" :loading="loading">刷新</Button>
    </div>

    <p class="muted" style="margin: -6px 0 14px; font-size: 12.5px">
      配置变更实时（秒级）自动下发到各服务器节点并生效，无需手动应用。
    </p>

    <Spinner v-if="loading && !st" />

    <template v-else-if="st">
      <!-- 统计卡片行 -->
      <div class="stat-grid">
        <div class="card stat">
          <span class="stat-label">用户数</span>
          <span class="stat-num">{{ st.counts.users }}</span>
        </div>
        <div class="card stat">
          <span class="stat-label">服务器节点</span>
          <span class="stat-num">
            {{ st.counts.servers_online }}<small class="muted stat-sub">/{{ st.counts.servers }} 在线</small>
          </span>
        </div>
        <div class="card stat">
          <span class="stat-label">规则数</span>
          <span class="stat-num">{{ st.counts.rules }}</span>
        </div>
        <div class="card stat">
          <span class="stat-label">规则集数</span>
          <span class="stat-num">{{ st.counts.rulesets }}</span>
        </div>
      </div>

      <!-- 流量概览 -->
      <div class="card">
        <h3 class="card-title">流量统计</h3>
        <div class="tflow">
          <div class="tf-item">
            <span class="tf-k">总上行</span>
            <span class="tf-v mono">↑ {{ fmtBytes(totalUp) }}</span>
          </div>
          <div class="tf-item">
            <span class="tf-k">总下行</span>
            <span class="tf-v mono">↓ {{ fmtBytes(totalDown) }}</span>
          </div>
          <div class="tf-item">
            <span class="tf-k">合计</span>
            <span class="tf-v mono total">{{ fmtBytes(totalUp + totalDown) }}</span>
          </div>
        </div>
      </div>

      <div class="grid2">
        <!-- 节点列表 -->
        <div class="card">
          <h3 class="card-title">
            节点列表
            <div class="spacer"></div>
            <router-link to="/servers" class="more">管理 →</router-link>
          </h3>
          <Empty v-if="!servers.length" text="暂无服务器节点" />
          <div v-else class="srv-list">
            <div v-for="s in servers" :key="s.sid" class="srv-row" @click="router.push('/servers')">
              <span class="dot" :class="{ on: s.online }"></span>
              <span class="srv-name">{{ s.name }}</span>
              <Badge :color="s.synced ? 'green' : 'yellow'">{{ s.synced ? '已同步' : '待同步' }}</Badge>
              <span class="mono muted srv-tr">↑{{ fmtBytes(s.traffic?.up) }} ↓{{ fmtBytes(s.traffic?.down) }}</span>
              <span class="muted srv-seen">{{ fmtAgo(s.last_seen) }}</span>
            </div>
          </div>
        </div>

        <!-- 流量排名 -->
        <div class="card">
          <h3 class="card-title">流量排名 · 用户</h3>
          <Empty v-if="!userRank.length" text="暂无流量数据" />
          <div v-for="r in userRank" :key="'u' + r.name" class="rank-row">
            <span class="rank-name" :title="r.name">{{ r.name }}</span>
            <div class="bar"><i :style="{ width: r.pct + '%' }"></i></div>
            <span class="mono rank-val">{{ fmtBytes(r.total) }}</span>
          </div>

          <h3 class="card-title" style="margin-top: 20px">流量排名 · 节点</h3>
          <Empty v-if="!serverRank.length" text="暂无流量数据" />
          <div v-for="r in serverRank" :key="'s' + r.name" class="rank-row">
            <span class="rank-name" :title="r.name">{{ r.name }}</span>
            <div class="bar"><i class="alt" :style="{ width: r.pct + '%' }"></i></div>
            <span class="mono rank-val">{{ fmtBytes(r.total) }}</span>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Empty from '@/component/ui/Empty.vue'
import Spinner from '@/component/ui/Spinner.vue'
import { get } from '@/util/request'
import { toast } from '@/util/toast'
import { fmtAgo, fmtBytes } from '@/util/format'
import type { ServerItem, StatusData, TrafficData } from '@/types'

const router = useRouter()
const st = ref<StatusData>()
const servers = ref<ServerItem[]>([])
const traffic = ref<TrafficData>({ users: {}, servers: {} })
const loading = ref(false)

const totalUp = computed(() => Object.values(traffic.value.users).reduce((a, t) => a + (t?.up || 0), 0))
const totalDown = computed(() => Object.values(traffic.value.users).reduce((a, t) => a + (t?.down || 0), 0))

function rankOf(entries: Array<[string, number]>, names?: Record<string, string>) {
  const arr = entries
    .map(([key, total]) => ({ name: names?.[key] ?? key, total }))
    .filter((x) => x.total > 0)
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
  const max = arr[0]?.total || 1
  return arr.map((x) => ({ ...x, pct: Math.max(3, Math.round((x.total / max) * 100)) }))
}

const userRank = computed(() =>
  rankOf(Object.entries(traffic.value.users).map(([name, t]) => [name, (t?.up || 0) + (t?.down || 0)])),
)

const serverRank = computed(() => {
  const names = Object.fromEntries(servers.value.map((s) => [s.sid, s.name]))
  return rankOf(
    Object.entries(traffic.value.servers).map(([sid, t]) => [sid, (t?.up || 0) + (t?.down || 0)]),
    names,
  )
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

onMounted(loadAll)
</script>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 14px;
  margin-bottom: 16px;
}

.stat {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 16px 18px;
}

.stat-label {
  font-size: 12.5px;
  color: var(--c-text-dim);
}

.stat-num {
  font-size: 26px;
  font-weight: 700;
  line-height: 1.2;
}

.stat-sub {
  font-size: 13px;
  font-weight: 400;
}

.tflow {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px;
}

.tf-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 12px 14px;
  border: 1px dashed var(--c-border);
  border-radius: 8px;
}

.tf-k {
  font-size: 12.5px;
  color: var(--c-text-dim);
}

.tf-v {
  font-size: 18px;
  font-weight: 600;
}

.tf-v.total {
  color: var(--c-primary);
}

.grid2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: 16px;
  margin-top: 16px;
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
  gap: 10px;
  padding: 9px 8px;
  border-radius: 8px;
  border-bottom: 1px dashed var(--c-border);
  cursor: pointer;
  transition: background-color 0.12s ease;
}

.srv-row:last-child {
  border-bottom: none;
}

.srv-row:hover {
  background: var(--c-hover);
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--c-text-dim);
  flex-shrink: 0;
}

.dot.on {
  background: var(--c-green);
  box-shadow: 0 0 5px var(--c-green);
}

.srv-name {
  font-weight: 600;
  font-size: 13.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.srv-tr {
  margin-left: auto;
  font-size: 12px;
}

.srv-seen {
  font-size: 12px;
  width: 74px;
  text-align: right;
  flex-shrink: 0;
}

.rank-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 0;
}

.rank-name {
  width: 110px;
  flex-shrink: 0;
  font-size: 13px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.bar {
  flex: 1;
  height: 8px;
  border-radius: 5px;
  background: var(--c-card-2);
  overflow: hidden;
}

.bar i {
  display: block;
  height: 100%;
  border-radius: 5px;
  background: var(--c-primary);
  transition: width 0.3s ease;
}

.bar i.alt {
  background: var(--c-green);
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

  .srv-seen {
    display: none;
  }
}
</style>
