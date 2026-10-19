<template>
  <div class="page">
    <div class="page-head">
      <h2>服务器节点</h2>
      <div class="spacer"></div>
      <Button small @click="load" :loading="loading">刷新</Button>
      <Button variant="primary" @click="openAdd">添加节点</Button>
    </div>
    <p class="page-sub">节点通过一键命令接入；配置保存后由节点自动拉取，hash 一致才显示「已同步」。</p>

    <div class="card">
      <Spinner v-if="loading && !servers.length" />
      <Empty v-else-if="!servers.length" text="暂无服务器节点">
        <Button small variant="primary" @click="openAdd">添加第一个节点</Button>
      </Empty>
      <div v-else class="table-wrap">
        <table class="tbl">
          <thead>
            <tr>
              <th>名称</th>
              <th>地址</th>
              <th>证书</th>
              <th>状态</th>
              <th>用户</th>
              <th>流量</th>
              <th>启用</th>
              <th style="width: 290px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in servers" :key="s.sid">
              <td>
                <Badge>{{ s.name }}</Badge>
                <div class="mono faint sid">{{ s.sid }}</div>
              </td>
              <td>
                <template v-if="s.ip_status">
                  <div v-for="f in (['ipv4', 'ipv6'] as const)" :key="f" class="addr-fam">
                    <span class="fam-tag mono">{{ f === 'ipv4' ? 'v4' : 'v6' }}</span>
                    <span v-if="!s.ip_status[f].enabled" class="faint">已停用</span>
                    <span v-else-if="s.ip_status[f].active" class="mono">{{ s.ip_status[f].address }}:{{ s.port }}</span>
                    <span
                      v-else-if="s.ip_status[f].reported_ip && s.ip_status[f].error"
                      class="fam-warn"
                      :title="`上报 ${s.ip_status[f].reported_ip} · ${s.ip_status[f].error}`"
                    >⚠ {{ famWarnText(s, f) }}</span>
                    <span v-else class="muted">{{ s.ip_status[f].error || '等待上报' }}</span>
                  </div>
                </template>
                <span v-else class="muted">待上报</span>
              </td>
              <td>
                <Badge :color="certModeColor(s.cert_mode)">{{ certModeLabel(s.cert_mode) }}</Badge>
                <div class="cert-exp" :class="certExpCls(s)" :title="s.cert_issuer ? `签发者: ${s.cert_issuer}` : ''">{{ certExpText(s) }}</div>
              </td>
              <td>
                <div class="row" style="gap: 6px">
                  <Badge :color="s.online ? 'green' : 'dim'">
                    <span class="dot" :class="{ on: s.online }"></span>{{ s.online ? '在线' : '离线' }}
                  </Badge>
                  <Badge v-if="s.sb_running === true" color="cyan">核心运行中</Badge>
                  <Badge v-else-if="s.sb_running === false" color="red">核心停止</Badge>
                  <Badge :color="s.synced ? 'green' : 'yellow'">{{ s.synced ? '已同步' : '待同步' }}</Badge>
                </div>
                <div class="mono faint" style="font-size: 11.5px; margin-top: 3px">
                  {{ fmtAgo(s.last_seen) }}<template v-if="s.agent_version"> · v{{ s.agent_version }}</template>
                </div>
                <div v-if="s.last_error" class="last-err" :title="s.last_error">⚠ {{ truncate(s.last_error, 40) }}</div>
              </td>
              <td>
                <Badge v-if="s.users_mode === 'none'" color="red">无用户</Badge>
                <Badge v-else-if="s.users_mode === 'all'" color="dim">全部</Badge>
                <Badge v-else color="cyan" :title="s.users.join('\n')" style="cursor: default">{{ s.users.length }} 人</Badge>
              </td>
              <td class="mono">↑{{ fmtBytes(s.traffic?.up) }} ↓{{ fmtBytes(s.traffic?.down) }}</td>
              <td><Toggle :model-value="s.enabled" @update:model-value="toggleEnable(s, $event)" /></td>
              <td>
                <div class="row" style="gap: 6px">
                  <Button small @click="openEdit(s)">编辑</Button>
                  <Button small @click="openRoute(s)">分流</Button>
                  <Button small title="重新生成部署命令，旧 token 立即失效" @click="resetToken(s)">重新部署</Button>
                  <Button small @click="preview(s)">配置</Button>
                  <Button small variant="danger" @click="del(s)">删除</Button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 添加 / 编辑节点 -->
    <Modal v-model:visible="editVisible" :title="editing ? `编辑节点: ${editing.name}` : '添加服务器节点'">
      <div class="form-grid">
        <Input v-model="form.name" label="名称" placeholder="如 香港-01" />
        <Input v-model.number="form.port" label="端口" type="number" placeholder="18443" />
        <Select v-model="form.ip_mode" label="网络模式" :options="IP_MODES" />
        <Select v-model="form.cert_mode" label="证书模式" :options="CERT_MODES" />
        <template v-if="form.cert_mode === 'acme'">
          <Input
            v-if="form.ip_mode !== 'ipv6'"
            v-model="form.domain"
            label="IPv4 域名"
            hint="需要 A 记录解析到该节点 IPv4, 并放行 80 端口用于验证"
            placeholder="node1.example.com"
          />
          <Input
            v-if="form.ip_mode !== 'ipv4'"
            v-model="form.domain6"
            label="IPv6 域名"
            :hint="form.ip_mode === 'dual' ? '需要 AAAA 记录; 双栈可后补, 未就绪时自动暂停 IPv6 入口' : '需要 AAAA 记录解析到该节点 IPv6, 并放行 80 端口用于验证'"
            placeholder="node1-v6.example.com"
          />
          <Input v-model="form.acme_email" label="ACME 邮箱" hint="可选" placeholder="admin@example.com" />
        </template>
        <p v-else-if="form.cert_mode === 'selfip'" class="muted cert-tip">
          按节点 IP 签发自签证书，客户端需允许不安全连接 (allowInsecure)。
        </p>
        <div v-else class="cert-tip">
          <Toggle v-model="form.unsafe_ok" label="我了解不安全模式的风险" />
          <p class="muted" style="margin: 6px 0 0; font-size: 12.5px">不申请可信证书，仅建议临时调试使用。</p>
        </div>
        <div class="fw">
          <Select v-model="form.users_mode" label="用户分配" :options="USER_MODES" />
        </div>
        <div v-if="form.users_mode === 'selected'" class="fw">
          <MultiSelect v-model="form.users" :options="userNames" label="指定用户" hint="仅所选用户可使用此节点" />
        </div>
        <p v-else-if="form.users_mode === 'none'" class="muted cert-tip">此节点不下发任何用户，仅保留节点与配置。</p>
        <Input v-model="form.note" label="备注" placeholder="可留空" />
      </div>
      <template #footer>
        <Button @click="editVisible = false">取消</Button>
        <Button variant="primary" :loading="saving" @click="save">{{ editing ? '保存' : '创建' }}</Button>
      </template>
    </Modal>

    <!-- 部署命令（token 仅显示一次） -->
    <Modal v-model:visible="installVisible" title="重新部署节点">
      <p class="warn-big">请立即复制部署命令，token 仅显示这一次。</p>
      <CodeBox :text="installCmd" multiline />
      <p v-if="caFingerprint" class="muted ca-fp" :title="`完整指纹: ${caFingerprint}`">
        面板 CA 指纹: {{ caFingerprint.slice(0, 32) }}… (可在节点侧用 openssl x509 -in /etc/ksing/panel-ca.pem -outform der | sha256sum 比对)
      </p>
      <div class="row" style="margin-top: 12px; justify-content: flex-end">
        <CopyButton :text="installCmd" label="复制部署命令" />
      </div>
      <p class="muted" style="margin: 12px 0 0; font-size: 12.5px">
        在节点上重新执行以下命令即可刷新部署；token 每次重新生成，旧 token 立即失效。
      </p>
      <template #footer>
        <Button variant="primary" @click="installVisible = false">我已保存</Button>
      </template>
    </Modal>

    <!-- 节点分流 -->
    <Drawer v-model:visible="routeVisible" :title="`节点分流 · ${routeServer?.name ?? ''}`" width="640px">
      <p class="muted" style="margin: 0 0 14px; font-size: 12.5px">
        以下规则只在该节点生效，对该节点全体用户生效。
      </p>
      <RuleScopePanel v-if="routeVisible && routeServer" :node-sid="routeServer.sid" />
      <template #footer>
        <Button @click="routeVisible = false">关闭</Button>
      </template>
    </Drawer>

    <!-- 下发配置预览 -->
    <Drawer v-model:visible="cfgVisible" :title="`下发配置: ${cfgServer?.name ?? ''}`" width="560px">
      <Spinner v-if="cfgLoading" />
      <template v-else-if="cfg">
        <div class="kv"><span class="k">配置 hash</span><span class="v mono">{{ cfg.hash.slice(0, 16) }}…</span></div>
        <div class="kv" style="margin-bottom: 12px"><span class="k">关联规则集</span><span class="v">{{ cfg.rulesets.length ? cfg.rulesets.map((r) => r.tag).join(', ') : '无' }}</span></div>
        <CodeBox :text="cfgText" multiline />
      </template>
      <template #footer>
        <Button @click="cfgVisible = false">关闭</Button>
      </template>
    </Drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
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
import RuleScopePanel from '@/component/widget/RuleScopePanel.vue'
import { del as httpDel, get, post, put } from '@/util/request'
import { confirmDialog } from '@/util/confirm'
import { toast } from '@/util/toast'
import { fmtAgo, fmtBytes, fmtTime } from '@/util/format'
import type { ServerConfigPreview, ServerCreated, ServerItem, UserInfo } from '@/types'

const CERT_MODES = [
  { label: '域名证书 (自动申请续签)', value: 'acme' },
  { label: 'IP 自签证书', value: 'selfip' },
  { label: '不安全模式 (自签)', value: 'unsafe' },
]

const IP_MODES = [
  { label: '双栈 (IPv4 + IPv6)', value: 'dual' },
  { label: '仅 IPv4', value: 'ipv4' },
  { label: '纯 IPv6', value: 'ipv6' },
]
const USER_MODES = [
  { label: '全部用户', value: 'all' },
  { label: '指定用户', value: 'selected' },
  { label: '无用户（暂停下放）', value: 'none' },
]

const servers = ref<ServerItem[]>([])
const userNames = ref<string[]>([])
const loading = ref(true)
let timer: ReturnType<typeof setInterval> | undefined

const editVisible = ref(false)
const editing = ref<ServerItem | null>(null)
const saving = ref(false)
const form = reactive({
  name: '',
  port: 18443,
  ip_mode: 'dual' as 'dual' | 'ipv4' | 'ipv6',
  cert_mode: 'selfip' as 'acme' | 'selfip' | 'unsafe',
  domain: '',
  domain6: '',
  acme_email: '',
  unsafe_ok: false,
  users_mode: 'all' as 'all' | 'selected' | 'none',
  users: [] as string[],
  note: '',
})

// 切换网络模式时清空不适用的域名
watch(
  () => form.ip_mode,
  (m) => {
    if (m === 'ipv4') form.domain6 = ''
    if (m === 'ipv6') form.domain = ''
  },
)

const installVisible = ref(false)
const installCmd = ref('')
const caFingerprint = ref('')

const routeVisible = ref(false)
const routeServer = ref<ServerItem>()

const cfgVisible = ref(false)
const cfgLoading = ref(false)
const cfgServer = ref<ServerItem>()
const cfg = ref<ServerConfigPreview>()
const cfgText = computed(() => (cfg.value ? JSON.stringify(cfg.value.config, null, 2) : ''))

function certModeLabel(m: ServerItem['cert_mode']): string {
  return { acme: '域名证书', selfip: 'IP 自签', unsafe: '不安全' }[m || 'selfip']
}

function certModeColor(m: ServerItem['cert_mode']): 'green' | 'yellow' | 'red' {
  return { acme: 'green', selfip: 'yellow', unsafe: 'red' }[m || 'selfip'] as 'green' | 'yellow' | 'red'
}

function certExpText(s: ServerItem): string {
  if (!s.cert_not_after) return '未上报'
  const now = Date.now() / 1000
  if (s.cert_not_after <= now) return '已过期'
  const days = Math.floor((s.cert_not_after - now) / 86400)
  if (days < 10) return days < 1 ? '即将过期' : `${days} 天后过期`
  return fmtTime(s.cert_not_after).slice(0, 10)
}

function certExpCls(s: ServerItem): string {
  if (!s.cert_not_after) return 'faint'
  const now = Date.now() / 1000
  if (s.cert_not_after <= now) return 'exp-red'
  if ((s.cert_not_after - now) / 86400 < 10) return 'exp-yellow'
  return 'faint'
}

function truncate(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) + '…' : text
}

function famWarnText(s: ServerItem, f: 'ipv4' | 'ipv6'): string {
  const err = s.ip_status?.[f]?.error || ''
  if (f === 'ipv6') return `IPv6 已检测到，但 ${err}，已暂停 IPv6 入口`
  return `IPv4 异常: ${err}`
}

async function load() {
  loading.value = true
  try {
    servers.value = await get<ServerItem[]>('/api/servers')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

async function ensureUsers() {
  try {
    const us = await get<UserInfo[]>('/api/users')
    userNames.value = us.map((u) => u.name)
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

function openAdd() {
  editing.value = null
  Object.assign(form, {
    name: '',
    port: 18443,
    ip_mode: 'dual',
    cert_mode: 'selfip',
    domain: '',
    domain6: '',
    acme_email: '',
    unsafe_ok: false,
    users_mode: 'all',
    users: [],
    note: '',
  })
  ensureUsers()
  editVisible.value = true
}

function openEdit(s: ServerItem) {
  editing.value = s
  Object.assign(form, {
    name: s.name,
    port: s.port,
    ip_mode: s.ip_mode || 'dual',
    cert_mode: s.cert_mode || (s.domain || s.domain6 ? 'acme' : 'selfip'),
    domain: s.domain,
    domain6: s.domain6 || '',
    acme_email: s.acme_email,
    unsafe_ok: false,
    users_mode: s.users_mode,
    users: [...(s.users || [])],
    note: s.note,
  })
  ensureUsers()
  editVisible.value = true
}

async function save() {
  if (!form.name.trim()) {
    toast('请输入节点名称', 'error')
    return
  }
  const port = Number(form.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    toast('端口需为 1-65535 的数字', 'error')
    return
  }
  if (form.cert_mode === 'acme') {
    const d4 = form.domain.trim()
    const d6 = form.domain6.trim()
    if (form.ip_mode !== 'ipv6' && !d4) {
      toast('acme 模式需要配置 IPv4 域名', 'error')
      return
    }
    if (form.ip_mode === 'ipv6' && !d6) {
      toast('纯 IPv6 节点需要配置 IPv6 域名', 'error')
      return
    }
    if (d4 && d6 && d4.toLowerCase() === d6.toLowerCase()) {
      toast('IPv4 与 IPv6 域名不能相同', 'error')
      return
    }
  }
  if (form.cert_mode === 'unsafe' && !form.unsafe_ok) {
    toast('请先勾选确认了解不安全模式的风险', 'error')
    return
  }
  if (form.users_mode === 'selected' && !form.users.length) {
    toast('请选择至少一个用户，或把用户分配改为「无用户」', 'error')
    return
  }
  const domain = form.cert_mode === 'acme' && form.ip_mode !== 'ipv6' ? form.domain.trim() : ''
  const domain6 = form.cert_mode === 'acme' && form.ip_mode !== 'ipv4' ? form.domain6.trim() : ''
  const acmeEmail = form.cert_mode === 'acme' ? form.acme_email.trim() : ''
  saving.value = true
  try {
    if (editing.value) {
      const body: Record<string, unknown> = {
        name: form.name.trim(),
        port,
        ip_mode: form.ip_mode,
        users_mode: form.users_mode,
        note: form.note,
        enabled: editing.value.enabled,
        cert_mode: form.cert_mode,
        domain,
        domain6,
        acme_email: acmeEmail,
      }
      if (form.users_mode === 'selected') body.users = form.users
      if (form.cert_mode === 'unsafe') body.unsafe_ok = true
      await put(`/api/servers/${editing.value.sid}`, body)
      toast('节点已更新，等待节点同步', 'success')
      editVisible.value = false
    } else {
      const body: Record<string, unknown> = {
        name: form.name.trim(), port, cert_mode: form.cert_mode, users_mode: form.users_mode,
        ip_mode: form.ip_mode,
      }
      if (domain) body.domain = domain
      if (domain6) body.domain6 = domain6
      if (acmeEmail) body.acme_email = acmeEmail
      if (form.cert_mode === 'unsafe') body.unsafe_ok = true
      if (form.users_mode === 'selected') body.users = form.users
      if (form.note) body.note = form.note
      const r = await post<ServerCreated>('/api/servers', body)
      editVisible.value = false
      showInstall(r.install_command)
    }
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

async function toggleEnable(s: ServerItem, enabled: boolean) {
  try {
    await put(`/api/servers/${s.sid}`, { enabled })
    s.enabled = enabled
    toast(enabled ? `已启用 ${s.name}` : `已禁用 ${s.name}`, 'success')
    await load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

async function showInstall(cmd: string) {
  installCmd.value = cmd
  installVisible.value = true
  try {
    const r = await get<{ agent_port: number; ca_fingerprint: string }>('/api/agent-info')
    caFingerprint.value = r.ca_fingerprint || ''
  } catch {
    caFingerprint.value = ''
  }
}

async function resetToken(s: ServerItem) {
  if (!(await confirmDialog(`重新部署节点「${s.name}」？\n将生成新的部署命令，旧 token 立即失效。`))) return
  try {
    const r = await post<ServerCreated>(`/api/servers/${s.sid}/token`)
    showInstall(r.install_command)
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

function openRoute(s: ServerItem) {
  routeServer.value = s
  routeVisible.value = true
}

async function preview(s: ServerItem) {
  cfgServer.value = s
  cfg.value = undefined
  cfgLoading.value = true
  cfgVisible.value = true
  try {
    cfg.value = await get<ServerConfigPreview>(`/api/servers/${s.sid}/config`)
  } catch (e) {
    toast((e as Error).message, 'error')
    cfgVisible.value = false
  } finally {
    cfgLoading.value = false
  }
}

async function del(s: ServerItem) {
  if (!(await confirmDialog(`确定删除服务器节点「${s.name}」？\n节点上的 agent 将无法再连接面板。`))) return
  try {
    await httpDel(`/api/servers/${s.sid}`)
    toast('已删除', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

onMounted(() => {
  load()
  timer = setInterval(() => {
    if (!document.hidden) load()
  }, 20000)
})

onUnmounted(() => clearInterval(timer))
</script>

<style scoped>
.sid {
  font-size: 11.5px;
  margin-top: 3px;
}

.addr-fam {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
}

.addr-fam + .addr-fam {
  margin-top: 3px;
}

.fam-tag {
  color: var(--c-text-faint);
  width: 16px;
  flex-shrink: 0;
}

.fam-warn {
  color: var(--c-yellow);
  max-width: 230px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: help;
}

.cert-exp {
  font-size: 11.5px;
  margin-top: 3px;
}

.exp-red {
  color: var(--c-red);
}

.exp-yellow {
  color: var(--c-yellow);
}

.last-err {
  color: var(--c-red);
  font-size: 11.5px;
  margin-top: 3px;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.fw {
  grid-column: 1 / -1;
}

.cert-tip {
  align-self: end;
  margin: 0;
  font-size: 12.5px;
  padding-bottom: 8px;
}

.warn-big {
  margin: 0 0 12px;
  color: var(--c-yellow);
  font-size: 14px;
  font-weight: 600;
}

.ca-fp {
  margin: 10px 0 0;
  font-size: 12px;
  line-height: 1.6;
  word-break: break-all;
}
</style>
