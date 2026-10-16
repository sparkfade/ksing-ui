<template>
  <div class="page">
    <div class="page-head">
      <h2>用户</h2>
      <div class="spacer"></div>
      <Button variant="primary" @click="openAdd">添加用户</Button>
    </div>
    <p class="page-sub">用户被禁用、到期或超额后，订阅自动失效并秒级从节点剔除。</p>

    <div class="card">
      <Spinner v-if="loading" />
      <Empty v-else-if="!users.length" text="暂无用户">
        <Button small variant="primary" @click="openAdd">添加第一个用户</Button>
      </Empty>
      <div v-else class="table-wrap">
        <table class="tbl">
          <thead>
            <tr>
              <th>用户</th>
              <th>状态</th>
              <th style="min-width: 170px">用量</th>
              <th>到期时间</th>
              <th>重置日</th>
              <th>订阅 token</th>
              <th>启用</th>
              <th style="width: 330px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in users" :key="u.name">
              <td>
                <Badge>{{ u.name }}</Badge>
                <div v-if="u.note" class="faint" style="font-size: 11.5px; margin-top: 3px">{{ u.note }}</div>
              </td>
              <td><Badge :color="userStatus(u).color">{{ userStatus(u).text }}</Badge></td>
              <td>
                <div class="use">
                  <div class="meter"><i :class="useCls(u)" :style="{ width: usePct(u) + '%' }"></i></div>
                  <span class="mono use-txt" :class="{ 'over-red': trafficOver(u) }">
                    {{ fmtBytes(usedBytes(u)) }} / {{ u.traffic_limit ? fmtBytes(u.traffic_limit) : '不限' }}
                  </span>
                </div>
              </td>
              <td class="mono" :class="{ 'over-red': isExpired(u) }">{{ u.expire_at ? fmtTime(u.expire_at) : '永久' }}</td>
              <td class="muted">{{ u.reset_day ? `每月 ${u.reset_day} 号` : '不重置' }}</td>
              <td>
                <div class="row" style="gap: 6px">
                  <span class="mono muted">{{ u.token.slice(0, 6) }}…</span>
                  <CopyButton :text="u.token" small />
                </div>
              </td>
              <td><Toggle :model-value="u.enable" @update:model-value="toggleEnable(u, $event)" /></td>
              <td>
                <div class="row" style="gap: 6px">
                  <Button small @click="openLink(u)">订阅</Button>
                  <Button small @click="openEdit(u)">编辑</Button>
                  <Button small @click="openRoute(u)">分流</Button>
                  <Button small title="按天数顺延到期时间" @click="openRenew(u)">续期</Button>
                  <Button small title="当前周期流量清零并恢复使用" @click="resetUsage(u)">流量</Button>
                  <Button small variant="danger" @click="del(u)">删除</Button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 添加用户 -->
    <Drawer v-model:visible="addVisible" title="添加用户">
      <div class="form-grid">
        <Input v-model="addForm.name" label="用户名" hint="字母/数字/_/-, 1-32 位" placeholder="用户名" />
        <Input v-model="addForm.password" label="AnyTLS 密码" hint="留空自动生成" placeholder="可留空" />
        <Input v-model="addForm.panel_password" label="面板登录密码" hint="留空则不能登录面板" placeholder="可留空" />
        <Input v-model="addForm.note" label="备注" placeholder="可留空" />
        <Input v-model.number="addForm.traffic_limit_gb" label="流量限制 (GB)" hint="0 = 不限" type="number" placeholder="0" />
        <Input v-model="addForm.expire_local" label="到期时间" hint="留空 = 不过期" type="datetime-local" />
        <Input v-model.number="addForm.reset_day" label="每月重置日" hint="0-31, 0 = 不按月重置" type="number" placeholder="0" />
      </div>
      <template #footer>
        <Button @click="addVisible = false">取消</Button>
        <Button variant="primary" :loading="saving" @click="addUser">创建</Button>
      </template>
    </Drawer>

    <!-- 订阅与节点 -->
    <Drawer v-model:visible="linkVisible" :title="`订阅 · ${current?.name ?? ''}`">
      <template v-if="current">
        <h4 class="sec">AnyTLS 密码</h4>
        <div class="row" style="gap: 6px">
          <span class="mono">{{ revealed.has(current.name) ? current.password : '••••••••' }}</span>
          <button class="eye" @click="toggleReveal(current.name)">{{ revealed.has(current.name) ? '隐藏' : '显示' }}</button>
          <CopyButton :text="current.password" small />
        </div>

        <h4 class="sec">节点链接</h4>
        <template v-if="currentLinks.length">
          <div v-for="(link, i) in currentLinks" :key="i" class="link-item">
            <p class="link-name">{{ linkName(link, i) }}</p>
            <CodeBox :text="link" />
            <div class="qr-row">
              <QrCode v-if="i === 0" :text="link" />
              <CopyButton :text="link" :label="`复制链接 ${i + 1}`" />
            </div>
          </div>
        </template>
        <p v-else class="muted">暂无可用节点链接（用户不可用或未分配节点）。</p>

        <h4 class="sec">订阅地址</h4>
        <template v-if="subEntries.length">
          <div v-for="e in subEntries" :key="e.key" class="sub-line">
            <span class="sub-label">{{ e.label }}</span>
            <CodeBox :text="e.url" class="sub-box" />
            <CopyButton :text="e.url" label="复制" />
          </div>
          <div class="qr-row">
            <QrCode :text="subEntries[0].url" />
          </div>
          <p class="muted hint">按客户端类型选择订阅地址；无法识别时会按 UA 自动判断，直接填 v2rayN 那条通常也能用。</p>
        </template>
        <p v-else class="muted">暂无订阅地址</p>
        <div class="row" style="margin-top: 10px">
          <Button small @click="resetSubToken">重置订阅链接</Button>
          <span class="muted" style="font-size: 12.5px">旧订阅链接立即失效，需重新分发</span>
        </div>

        <h4 class="sec">可见节点</h4>
        <p class="muted" style="margin: 0 0 10px; font-size: 12.5px">控制该用户的订阅与可用节点；不选 = 全部节点。</p>
        <MultiSelect v-model="serverSel" :options="serverOptions" />
        <div class="row" style="margin-top: 12px; justify-content: flex-end">
          <Button small variant="primary" :loading="savingServers" @click="saveServers">保存可见节点</Button>
        </div>
      </template>
      <template #footer>
        <Button @click="linkVisible = false">关闭</Button>
      </template>
    </Drawer>

    <!-- 用户分流 -->
    <Drawer v-model:visible="routeVisible" :title="`用户分流 · ${routeUser?.name ?? ''}`" width="640px">
      <template v-if="routeUser">
        <h4 class="sec" style="margin-top: 0">专属默认出口</h4>
        <div class="row">
          <span class="muted">当前:</span>
          <Badge v-if="userFinal" :color="userFinal === 'reject' ? 'red' : userFinal === 'direct' ? 'dim' : 'cyan'">{{ userFinal }}</Badge>
          <Badge v-else color="dim">跟随全局</Badge>
        </div>
        <div class="row" style="margin-top: 10px">
          <Select v-model="ufOutbound" :options="outboundOptions" style="flex: 1" />
          <Button small variant="primary" :loading="ufSaving" @click="saveFinal">保存</Button>
          <Button v-if="userFinal" small variant="danger" :loading="ufSaving" @click="delFinal">删除</Button>
        </div>

        <h4 class="sec">专属规则</h4>
        <RuleScopePanel v-if="routeVisible" :user-name="routeUser.name" />
      </template>
      <template #footer>
        <Button @click="routeVisible = false">关闭</Button>
      </template>
    </Drawer>

    <!-- 编辑用户 -->
    <Drawer v-model:visible="editVisible" :title="`编辑用户: ${current?.name ?? ''}`">
      <template v-if="current">
        <div class="form-grid">
          <Input v-model="editForm.note" label="备注" placeholder="备注信息" />
          <Input v-model.number="editForm.traffic_limit_gb" label="流量限制 (GB)" hint="0 = 不限" type="number" placeholder="0" />
          <Input v-model="editForm.expire_local" label="到期时间" hint="留空 = 不过期" type="datetime-local" />
          <Input v-model.number="editForm.reset_day" label="每月重置日" hint="0-31, 0 = 不按月重置" type="number" placeholder="0" />

          <div class="field-wide">
            <Toggle v-model="editForm.resetPassword" label="重置 AnyTLS 密码" />
            <Input
              v-if="editForm.resetPassword"
              v-model="editForm.password"
              hint="留空则自动生成新密码"
              placeholder="新 AnyTLS 密码"
              style="margin-top: 8px"
            />
          </div>

          <Select v-model="editForm.panelMode" label="面板登录密码" :options="panelModeOptions" />
          <Input
            v-if="editForm.panelMode === 'set'"
            v-model="editForm.panel_password"
            label="新面板密码"
            placeholder="至少 6 位"
          />
        </div>
      </template>
      <template #footer>
        <Button @click="editVisible = false">取消</Button>
        <Button variant="primary" :loading="saving" @click="saveEdit">保存</Button>
      </template>
    </Drawer>

    <!-- 续期 -->
    <Modal v-model:visible="renewVisible" :title="`续期 · ${current?.name ?? ''}`">
      <Input v-model.number="renewDays" label="顺延天数" hint="从当前到期时间（已过期则从现在）顺延" type="number" placeholder="30" />
      <p class="muted" style="margin: 10px 0 0; font-size: 12.5px">保存后实时生效，秒级下发到相关节点。</p>
      <template #footer>
        <Button @click="renewVisible = false">取消</Button>
        <Button variant="primary" :loading="renewing" @click="doRenew">续期</Button>
      </template>
    </Modal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Drawer from '@/component/ui/Drawer.vue'
import Empty from '@/component/ui/Empty.vue'
import Input from '@/component/ui/Input.vue'
import Modal from '@/component/ui/Modal.vue'
import MultiSelect from '@/component/ui/MultiSelect.vue'
import Select from '@/component/ui/Select.vue'
import Spinner from '@/component/ui/Spinner.vue'
import Toggle from '@/component/ui/Toggle.vue'
import CodeBox from '@/component/widget/CodeBox.vue'
import CopyButton from '@/component/widget/CopyButton.vue'
import QrCode from '@/component/widget/QrCode.vue'
import RuleScopePanel from '@/component/widget/RuleScopePanel.vue'
import { del as httpDel, get, post, put } from '@/util/request'
import { confirmDialog } from '@/util/confirm'
import { fmtBytes, fmtTime } from '@/util/format'
import { toast } from '@/util/toast'
import type { NodeInfo, RoutesData, ServerItem, SubUrls, UserInfo } from '@/types'

const SUB_FORMATS: Array<{ key: keyof SubUrls; label: string }> = [
  { key: 'singbox', label: 'sing-box' },
  { key: 'clash', label: 'mihomo·Clash' },
  { key: 'v2ray', label: 'v2rayN' },
]

const users = ref<UserInfo[]>([])
const loading = ref(true)
const saving = ref(false)
const revealed = ref(new Set<string>())
const servers = ref<ServerItem[]>([])
const nodeTags = ref<string[]>([])

const addVisible = ref(false)
const addForm = reactive({
  name: '',
  password: '',
  panel_password: '',
  note: '',
  traffic_limit_gb: 0,
  expire_local: '',
  reset_day: 0,
})

const linkVisible = ref(false)
const editVisible = ref(false)
const current = ref<UserInfo>()
const serverSel = ref<string[]>([])
const savingServers = ref(false)

const routeVisible = ref(false)
const routeUser = ref<UserInfo>()
const userFinal = ref('')
const ufOutbound = ref('direct')
const ufSaving = ref(false)

const renewVisible = ref(false)
const renewing = ref(false)
const renewDays = ref(30)

const serverOptions = computed(() => servers.value.map((s) => ({ label: s.name, value: s.sid })))

const outboundOptions = computed(() => [
  { label: 'direct 直连', value: 'direct' },
  { label: 'reject 拒绝', value: 'reject' },
  ...nodeTags.value.map((t) => ({ label: `节点: ${t}`, value: t })),
])

const subEntries = computed(() => {
  const u = current.value
  if (!u) return [] as Array<{ key: string; label: string; url: string }>
  const out = SUB_FORMATS.filter((f) => u.sub_urls?.[f.key]).map((f) => ({
    key: f.key,
    label: f.label,
    url: u.sub_urls![f.key]!,
  }))
  if (out.length) return out
  return u.sub_url ? [{ key: 'default', label: '通用', url: u.sub_url }] : []
})

const currentLinks = computed(() => {
  const u = current.value
  if (!u) return [] as string[]
  if (u.links?.length) return u.links
  return u.link ? [u.link] : []
})

function linkName(link: string, i: number): string {
  const h = link.split('#')[1]
  if (!h) return `链接 ${i + 1}`
  try {
    return decodeURIComponent(h)
  } catch {
    return h
  }
}

const panelModeOptions = [
  { label: '保持不变', value: 'keep' },
  { label: '设置新密码', value: 'set' },
  { label: '清除登录权限', value: 'clear' },
]
const editForm = reactive({
  note: '',
  traffic_limit_gb: 0,
  expire_local: '',
  reset_day: 0,
  resetPassword: false,
  password: '',
  panelMode: 'keep',
  panel_password: '',
})

function usedBytes(u: UserInfo): number {
  return (u.traffic?.up || 0) + (u.traffic?.down || 0)
}

function isExpired(u: UserInfo): boolean {
  return !!u.expire_at && u.expire_at * 1000 < Date.now()
}

function trafficOver(u: UserInfo): boolean {
  if (isExpired(u)) return true
  const lim = u.traffic_limit || 0
  return lim > 0 && usedBytes(u) >= lim
}

function usePct(u: UserInfo): number {
  const lim = u.traffic_limit || 0
  if (!lim) return 0
  return Math.min(100, Math.round((usedBytes(u) / lim) * 100))
}

function useCls(u: UserInfo): string {
  if (trafficOver(u)) return 'r'
  const p = usePct(u)
  if (p > 85) return 'r'
  if (p >= 60) return 'y'
  return ''
}

function userStatus(u: UserInfo): { color: 'green' | 'red' | 'dim'; text: string } {
  if (!u.enable) return { color: 'dim', text: '禁用' }
  if (u.active === false) {
    if (isExpired(u)) return { color: 'red', text: '已过期' }
    return { color: 'red', text: '已超额' }
  }
  return { color: 'green', text: '正常' }
}

function tsToLocalInput(ts: number): string {
  const d = new Date(ts * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

function quotaFields(gb: number | string, local: string, day: number | string): Record<string, number> {
  return {
    traffic_limit: Math.round((Number(gb) || 0) * 1073741824),
    expire_at: local ? Math.floor(new Date(local).getTime() / 1000) : 0,
    reset_day: Math.min(31, Math.max(0, Math.round(Number(day) || 0))),
  }
}

async function load() {
  loading.value = true
  try {
    const [us, sv, nd] = await Promise.all([
      get<UserInfo[]>('/api/users'),
      get<ServerItem[]>('/api/servers'),
      get<Record<string, NodeInfo>>('/api/nodes'),
    ])
    users.value = us
    servers.value = sv
    nodeTags.value = Object.keys(nd).sort()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

function toggleReveal(name: string) {
  const s = new Set(revealed.value)
  if (s.has(name)) s.delete(name)
  else s.add(name)
  revealed.value = s
}

async function toggleEnable(u: UserInfo, enable: boolean) {
  try {
    await put(`/api/users/${encodeURIComponent(u.name)}`, { enable })
    u.enable = enable
    toast(enable ? `已启用 ${u.name}` : `已禁用 ${u.name}`, 'success')
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

function openAdd() {
  Object.assign(addForm, { name: '', password: '', panel_password: '', note: '', traffic_limit_gb: 0, expire_local: '', reset_day: 0 })
  addVisible.value = true
}

async function addUser() {
  if (!addForm.name.trim()) {
    toast('请输入用户名', 'error')
    return
  }
  saving.value = true
  try {
    const body: Record<string, unknown> = { name: addForm.name.trim() }
    if (addForm.password) body.password = addForm.password
    if (addForm.panel_password) body.panel_password = addForm.panel_password
    if (addForm.note) body.note = addForm.note
    Object.assign(body, quotaFields(addForm.traffic_limit_gb, addForm.expire_local, addForm.reset_day))
    const r = await post<{ ok: boolean; password: string }>('/api/users', body)
    toast(`用户已创建，AnyTLS 密码: ${r.password}`, 'success')
    addVisible.value = false
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

function openLink(u: UserInfo) {
  current.value = u
  serverSel.value = [...(u.servers || [])]
  linkVisible.value = true
}

async function saveServers() {
  const u = current.value
  if (!u) return
  savingServers.value = true
  try {
    await put(`/api/users/${encodeURIComponent(u.name)}/servers`, { servers: serverSel.value })
    u.servers = [...serverSel.value]
    toast('可见节点已保存，已自动下发到相关节点', 'success')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    savingServers.value = false
  }
}

async function openRoute(u: UserInfo) {
  routeUser.value = u
  routeVisible.value = true
  ufOutbound.value = 'direct'
  userFinal.value = ''
  try {
    const rc = await get<RoutesData>('/api/routes')
    const f = rc.user_final?.[u.name]
    if (f) {
      userFinal.value = f
      ufOutbound.value = f
    }
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

async function saveFinal() {
  const u = routeUser.value
  if (!u) return
  ufSaving.value = true
  try {
    await post('/api/routes/final', { user: u.name, outbound: ufOutbound.value })
    userFinal.value = ufOutbound.value
    toast('专属出口已保存，已自动下发到相关节点', 'success')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    ufSaving.value = false
  }
}

async function delFinal() {
  const u = routeUser.value
  if (!u) return
  if (!(await confirmDialog(`删除用户「${u.name}」的专属默认出口？将恢复跟随全局默认。`))) return
  ufSaving.value = true
  try {
    await httpDel('/api/routes/final', { user: u.name })
    userFinal.value = ''
    ufOutbound.value = 'direct'
    toast('已删除，已自动下发到相关节点', 'success')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    ufSaving.value = false
  }
}

function openEdit(u: UserInfo) {
  current.value = u
  Object.assign(editForm, {
    note: u.note,
    traffic_limit_gb: u.traffic_limit ? +(u.traffic_limit / 1073741824).toFixed(2) : 0,
    expire_local: u.expire_at ? tsToLocalInput(u.expire_at) : '',
    reset_day: u.reset_day || 0,
    resetPassword: false,
    password: '',
    panelMode: 'keep',
    panel_password: '',
  })
  editVisible.value = true
}

function genPassword(): string {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789'
  const buf = new Uint8Array(16)
  crypto.getRandomValues(buf)
  return Array.from(buf, (b) => chars[b % chars.length]).join('')
}

async function saveEdit() {
  const u = current.value
  if (!u) return
  const body: Record<string, unknown> = { note: editForm.note }
  Object.assign(body, quotaFields(editForm.traffic_limit_gb, editForm.expire_local, editForm.reset_day))
  if (editForm.resetPassword) body.password = editForm.password || genPassword()
  if (editForm.panelMode === 'set') {
    if (!editForm.panel_password) {
      toast('请输入新面板密码', 'error')
      return
    }
    body.panel_password = editForm.panel_password
  } else if (editForm.panelMode === 'clear') {
    body.panel_password = ''
  }

  saving.value = true
  try {
    await put(`/api/users/${encodeURIComponent(u.name)}`, body)
    toast('已保存', 'success')
    editVisible.value = false
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

async function resetSub(u: UserInfo) {
  if (!(await confirmDialog(`重置用户「${u.name}」的订阅地址？\n旧订阅地址立即失效，需重新分发。`))) return
  try {
    await put(`/api/users/${encodeURIComponent(u.name)}`, { refresh_token: true })
    toast('订阅已重置，已自动下发到相关节点', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

async function resetSubToken() {
  if (current.value) await resetSub(current.value)
}

async function resetUsage(u: UserInfo) {
  if (!(await confirmDialog(`重置用户「${u.name}」的当前周期流量？\n流量清零并恢复使用。`))) return
  try {
    await post(`/api/users/${encodeURIComponent(u.name)}/reset_usage`)
    toast('流量已重置，已自动下发到相关节点', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

function openRenew(u: UserInfo) {
  current.value = u
  renewDays.value = 30
  renewVisible.value = true
}

async function doRenew() {
  const u = current.value
  if (!u) return
  const days = Math.round(Number(renewDays.value))
  if (!Number.isInteger(days) || days < 1) {
    toast('请输入有效的顺延天数', 'error')
    return
  }
  renewing.value = true
  try {
    await put(`/api/users/${encodeURIComponent(u.name)}`, { renew_days: days })
    toast(`已为 ${u.name} 续期 ${days} 天，已自动下发到相关节点`, 'success')
    renewVisible.value = false
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    renewing.value = false
  }
}

async function del(u: UserInfo) {
  if (!(await confirmDialog(`确定删除用户「${u.name}」？`))) return
  try {
    await httpDel(`/api/users/${encodeURIComponent(u.name)}`)
    toast('已删除', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

onMounted(load)
</script>

<style scoped>
.use {
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.use .meter {
  width: 100%;
}

.use-txt {
  font-size: 11.5px;
}

.over-red {
  color: var(--c-red);
  font-weight: 600;
}

.eye {
  background: none;
  border: none;
  color: var(--c-text-dim);
  cursor: pointer;
  font-size: 12px;
  padding: 2px 4px;
}

.eye:hover {
  color: var(--c-primary);
}

.sec {
  margin: 0 0 10px;
  font-size: 13.5px;
  color: var(--c-text-dim);
}

.sec:not(:first-child) {
  margin-top: 22px;
}

.qr-row {
  display: flex;
  align-items: flex-end;
  gap: 14px;
  margin-top: 12px;
  flex-wrap: wrap;
}

.link-item + .link-item {
  margin-top: 16px;
  padding-top: 14px;
  border-top: 1px dashed var(--c-border);
}

.link-name {
  margin: 0 0 8px;
  font-size: 12.5px;
  color: var(--c-text-dim);
}

.sub-line {
  display: flex;
  align-items: center;
  gap: 10px;
}

.sub-line + .sub-line {
  margin-top: 8px;
}

.sub-label {
  width: 92px;
  flex-shrink: 0;
  font-size: 12.5px;
  color: var(--c-text-dim);
}

.sub-box {
  flex: 1;
  min-width: 0;
}

.hint {
  margin: 12px 0 0;
  font-size: 12.5px;
}

.field-wide {
  grid-column: 1 / -1;
}
</style>
