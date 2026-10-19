<template>
  <div class="page">
    <template v-if="me">
      <!-- 概览 -->
      <div class="card hero">
        <div class="row wrap">
          <h2 class="hello">你好，{{ me.name }}</h2>
          <div class="spacer"></div>
          <Badge :color="me.enable ? 'green' : 'red'">{{ me.enable ? '账号正常' : '已禁用' }}</Badge>
          <Badge v-if="inactiveReason" color="red">{{ inactiveReason }}</Badge>
        </div>
        <div v-if="inactiveReason" class="tip-bar">
          账号当前不可用：{{ inactiveReason }}，节点与订阅均已停止下发，请联系管理员。
        </div>
      </div>

      <!-- 我的用量 -->
      <div class="card">
        <h3 class="card-title">
          我的用量
          <span class="sub" v-if="me.reset_day">每月 {{ me.reset_day }} 号重置</span>
        </h3>
        <div class="usage">
          <div class="usage-nums">
            <span class="usage-num mono">{{ fmtBytes(used) }}</span>
            <span class="muted usage-limit">/ {{ me.traffic_limit ? fmtBytes(me.traffic_limit) : '不限量' }}</span>
          </div>
          <div v-if="me.traffic_limit" class="meter" :class="{ tight: usagePct >= 90 }">
            <i :class="usagePct >= 90 ? 'r' : usagePct >= 70 ? 'y' : 'g'" :style="{ width: usagePct + '%' }"></i>
          </div>
          <div class="usage-meta muted mono">
            <span>↑ {{ fmtBytes(me.traffic?.up || 0) }}</span>
            <span>↓ {{ fmtBytes(me.traffic?.down || 0) }}</span>
            <span v-if="usagePct">已用 {{ usagePct.toFixed(1) }}%</span>
          </div>
        </div>
        <div class="kv-grid">
          <div class="kv"><span class="k">到期时间</span><span class="v mono">{{ me.expire_at ? fmtTime(me.expire_at) : '永久有效' }}</span></div>
          <div class="kv"><span class="k">当前出口</span><span class="v"><Badge :color="exitColor">{{ me.exit }}</Badge></span></div>
          <div class="kv"><span class="k">专属分流规则</span><span class="v mono">{{ me.my_rules }} 条</span></div>
        </div>
      </div>

      <!-- 订阅地址 -->
      <div class="card">
        <h3 class="card-title">
          订阅地址
          <span class="sub">导入客户端后自动跟随面板配置更新</span>
        </h3>
        <template v-if="subEntries.length">
          <div class="sub-list">
            <div v-for="e in subEntries" :key="e.key" class="sub-line">
              <button type="button" class="sub-label" :class="{ active: qrKey === e.key }" :aria-pressed="qrKey === e.key" @click="qrKey = e.key">{{ e.label }}</button>
              <CodeBox :text="e.url" class="sub-box" />
              <CopyButton :text="e.url" label="复制" />
            </div>
          </div>
          <div class="row wrap qr-area">
            <QrCode :text="qrUrl" />
            <p class="muted qr-tip">
              扫码导入「{{ qrLabel }}」订阅。<br />
              无法识别客户端类型时会按 UA 自动判断，直接填 v2rayN 那条通常也能用。
            </p>
            <div class="spacer"></div>
            <Button variant="danger" small :loading="resetting" @click="resetSub">重置订阅链接</Button>
          </div>
          <p class="card-note muted">重置后旧订阅地址立即失效，客户端需要重新导入。</p>
        </template>
        <Empty v-else text="暂无订阅地址，请使用下方 AnyTLS 链接" />
      </div>

      <!-- 节点链接 -->
      <div class="card">
        <h3 class="card-title">
          AnyTLS 节点链接
          <span class="sub">{{ links.length }} 条</span>
        </h3>
        <template v-if="links.length">
          <div v-for="(link, i) in links" :key="i" class="link-item">
            <p class="link-name">
              <span class="dot" :class="{ on: me.enable && me.active !== false }" aria-hidden="true"></span>
              {{ linkName(link, i) }}
            </p>
            <CodeBox :text="link" />
          </div>
          <div class="row wrap qr-area">
            <QrCode :text="links[0]" />
            <p class="muted qr-tip">扫码导入第一个节点（{{ linkName(links[0], 0) }}）。</p>
          </div>
        </template>
        <Empty v-else :text="me.enable ? '暂无可用服务器节点，请联系管理员' : '账号已禁用，暂无可用链接'" />
      </div>

      <!-- 修改密码 -->
      <div class="card">
        <h3 class="card-title">修改面板密码</h3>
        <div class="form-grid">
          <Input v-model="oldPwd" label="原密码" type="password" placeholder="当前面板密码" />
          <Input v-model="newPwd" label="新密码" hint="至少 6 位" type="password" placeholder="新密码" />
        </div>
        <div class="row foot">
          <span class="muted note">修改后当前会话保持登录，其他已登录会话立即失效。</span>
          <Button variant="primary" :loading="saving" @click="changePwd">修改密码</Button>
        </div>
      </div>
    </template>
    <Spinner v-else />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Empty from '@/component/ui/Empty.vue'
import Input from '@/component/ui/Input.vue'
import Spinner from '@/component/ui/Spinner.vue'
import CodeBox from '@/component/widget/CodeBox.vue'
import CopyButton from '@/component/widget/CopyButton.vue'
import QrCode from '@/component/widget/QrCode.vue'
import { get, post } from '@/util/request'
import { toast } from '@/util/toast'
import { confirmDialog } from '@/util/confirm'
import { auth, login } from '@/util/auth'
import { fmtBytes, fmtTime } from '@/util/format'
import type { MeInfo, SubUrls } from '@/types'

const me = ref<MeInfo>()
const saving = ref(false)
const resetting = ref(false)
const oldPwd = ref('')
const newPwd = ref('')
const qrKey = ref('')

const links = computed(() => {
  if (!me.value) return [] as string[]
  if (me.value.links?.length) return me.value.links
  return me.value.link ? [me.value.link] : []
})

function linkName(link: string, i: number): string {
  const h = link.split('#')[1]
  if (!h) return `节点 ${i + 1}`
  try {
    return decodeURIComponent(h)
  } catch {
    return h
  }
}

const SUB_FORMATS: Array<{ key: keyof SubUrls; label: string }> = [
  { key: 'singbox', label: 'sing-box' },
  { key: 'clash', label: 'mihomo·Clash' },
  { key: 'v2ray', label: 'v2rayN' },
]

function subEntriesOf(u: { sub_url: string; sub_urls?: SubUrls }): Array<{ key: string; label: string; url: string }> {
  const out = SUB_FORMATS.filter((f) => u.sub_urls?.[f.key]).map((f) => ({
    key: f.key,
    label: f.label,
    url: u.sub_urls![f.key]!,
  }))
  if (out.length) return out
  return u.sub_url ? [{ key: 'default', label: '通用', url: u.sub_url }] : []
}

const subEntries = computed(() => (me.value ? subEntriesOf(me.value) : []))

const qrUrl = computed(() => {
  const hit = subEntries.value.find((e) => e.key === qrKey.value)
  return hit ? hit.url : subEntries.value[0]?.url || ''
})

const qrLabel = computed(() => {
  const hit = subEntries.value.find((e) => e.key === qrKey.value)
  return hit ? hit.label : subEntries.value[0]?.label || ''
})

const used = computed(() => (me.value?.traffic?.up || 0) + (me.value?.traffic?.down || 0))

const usagePct = computed(() => {
  const lim = me.value?.traffic_limit || 0
  if (!lim) return 0
  return Math.min(100, (used.value / lim) * 100)
})

const exitColor = computed(() => {
  const e = me.value?.exit
  return e === 'reject' ? 'red' : e === 'direct' ? 'dim' : 'purple'
})

const inactiveReason = computed(() => {
  const m = me.value
  if (!m) return ''
  if (!m.enable) return '被禁用'
  if (m.active === false) {
    if (m.expire_at && m.expire_at * 1000 < Date.now()) return '已到期'
    return '已超额'
  }
  return ''
})

async function load() {
  try {
    me.value = await get<MeInfo>('/api/me')
    if (!qrKey.value) qrKey.value = subEntries.value[0]?.key || ''
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

async function changePwd() {
  if (newPwd.value.length < 6) {
    toast('新密码至少 6 位', 'error')
    return
  }
  saving.value = true
  try {
    const r = await post<{ ok: boolean; token?: string }>('/api/me/password', { old: oldPwd.value, new: newPwd.value })
    if (r.token) login(r.token, 'user', auth.name) // 旧会话已失效, 换新令牌
    toast('密码已修改', 'success')
    oldPwd.value = ''
    newPwd.value = ''
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

async function resetSub() {
  if (!(await confirmDialog('确定重置订阅链接？\n旧链接将立即失效，客户端需要重新导入。'))) return
  resetting.value = true
  try {
    const r = await post<{ ok: boolean; sub_url: string }>('/api/me/refresh_token', {})
    await load() // 重新拉取三格式地址
    toast('订阅链接已重置，旧链接已失效', 'success')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    resetting.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.hero .hello {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
}

.hero .tip-bar {
  margin: 12px 0 0;
}

/* 用量 */
.usage-nums {
  display: flex;
  align-items: baseline;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}

.usage-num {
  font-size: 26px;
  font-weight: 700;
}

.usage-limit {
  font-size: 13px;
}

.usage .meter {
  height: 10px;
}

.usage-meta {
  display: flex;
  gap: 18px;
  margin-top: 8px;
  font-size: 12.5px;
  flex-wrap: wrap;
}

.kv-grid {
  margin-top: 14px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 0 24px;
}

/* 订阅 */
.sub-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.sub-line {
  display: flex;
  align-items: center;
  gap: 10px;
}

.sub-label {
  width: 104px;
  flex-shrink: 0;
  font-size: 12.5px;
  font-family: var(--font);
  text-align: left;
  background: none;
  color: var(--c-text-dim);
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 6px;
  border: 1px solid transparent;
  transition: all 0.15s var(--ease);
}

.sub-label:hover {
  color: var(--c-text);
  background: var(--c-hover);
}

.sub-label.active {
  color: var(--c-primary);
  background: var(--c-primary-soft);
  border-color: var(--c-primary-bd);
}

.sub-box {
  flex: 1;
  min-width: 0;
}

.qr-area {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px dashed var(--c-border);
  align-items: center;
}

.qr-tip {
  margin: 0;
  font-size: 12.5px;
  line-height: 1.7;
}

.card-note {
  margin: 10px 0 0;
  font-size: 12.5px;
}

/* 节点链接 */
.link-item + .link-item {
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px dashed var(--c-border);
}

.link-name {
  margin: 0 0 8px;
  font-size: 13px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  word-break: break-all;
}

/* 密码 */
.foot {
  margin-top: 16px;
  justify-content: flex-end;
  flex-wrap: wrap;
}

.foot .note {
  font-size: 12.5px;
  margin-right: auto;
}

@media (max-width: 767px) {
  .sub-line {
    flex-wrap: wrap;
  }

  .sub-box {
    flex-basis: 100%;
    order: 3;
  }

  .qr-area {
    align-items: flex-start;
  }
}
</style>
