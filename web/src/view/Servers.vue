<template>
  <div>
    <div class="page-head">
      <h2>服务器节点</h2>
      <div class="spacer"></div>
      <Button small @click="load" :loading="loading">刷新</Button>
      <Button variant="primary" @click="openAdd">添加节点</Button>
    </div>

    <p class="muted" style="margin: -6px 0 14px; font-size: 12.5px">
      节点通过一键命令接入；配置变更实时（秒级）自动下发到相关节点并生效，无需手动应用。
    </p>

    <div class="card">
      <Spinner v-if="loading && !servers.length" />
      <Empty v-else-if="!servers.length" text="暂无服务器节点，点击右上角添加" />
      <div v-else class="table-wrap">
        <table class="tbl">
          <thead>
            <tr>
              <th>名称</th>
              <th>地址</th>
              <th>证书</th>
              <th>在线状态</th>
              <th>同步状态</th>
              <th>下放用户</th>
              <th>流量 (上行/下行)</th>
              <th>最近在线</th>
              <th style="width: 290px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in servers" :key="s.sid">
              <td>
                <Badge>{{ s.name }}</Badge>
                <div class="mono muted sid">{{ s.sid }}</div>
              </td>
              <td class="mono">
                <template v-if="s.cert_mode === 'acme'">
                  <Badge color="green" style="margin-right: 6px">域名</Badge>{{ s.domain }}:{{ s.port }}
                </template>
                <template v-else-if="s.reported_ip">{{ s.reported_ip }}:{{ s.port }}</template>
                <span v-else class="muted">待上报</span>
              </td>
              <td>
                <Badge :color="certModeColor(s.cert_mode)">{{ certModeLabel(s.cert_mode) }}</Badge>
                <div class="cert-exp" :class="certExpCls(s)" :title="s.cert_issuer ? `签发者: ${s.cert_issuer}` : ''">{{ certExpText(s) }}</div>
              </td>
              <td>
                <Badge :color="s.online ? 'green' : 'dim'">
                  <span class="dot" :class="{ on: s.online }"></span>{{ s.online ? '在线' : '离线' }}
                </Badge>
                <span v-if="s.online && s.agent_version" class="mono muted" style="margin-left: 6px">v{{ s.agent_version }}</span>
              </td>
              <td><Badge :color="s.synced ? 'green' : 'yellow'">{{ s.synced ? '已同步' : '待同步' }}</Badge></td>
              <td>
                <Badge v-if="!s.users?.length" color="dim">全部</Badge>
                <Badge v-else color="cyan" :title="s.users.join('\n')" style="cursor: default">{{ s.users.length }} 人</Badge>
              </td>
              <td class="mono">↑{{ fmtBytes(s.traffic?.up) }} ↓{{ fmtBytes(s.traffic?.down) }}</td>
              <td class="muted">{{ fmtAgo(s.last_seen) }}</td>
              <td>
                <div class="row" style="gap: 6px">
                  <Button small @click="openEdit(s)">编辑</Button>
                  <Button small @click="openRoute(s)">分流</Button>
                  <Button small title="重置部署命令，旧 token 立即失效" @click="resetToken(s)">部署</Button>
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
        <Select v-model="form.cert_mode" label="证书模式" :options="CERT_MODES" />
        <template v-if="form.cert_mode === 'acme'">
          <Input v-model="form.domain" label="域名" hint="请先将域名 A 记录解析到该节点 IP, 并放行 80 端口用于验证" placeholder="node1.example.com" />
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
          <MultiSelect v-model="form.users" :options="userNames" label="下放用户" hint="不选 = 全部用户" />
        </div>
        <Input v-model="form.note" label="备注" placeholder="可留空" />
        <div v-if="editing" class="field-row">
          <Toggle v-model="form.enabled" label="启用节点" />
        </div>
      </div>
      <template #footer>
        <Button @click="editVisible = false">取消</Button>
        <Button variant="primary" :loading="saving" @click="save">{{ editing ? '保存' : '创建' }}</Button>
      </template>
    </Modal>

    <!-- 安装命令（token 仅显示一次） -->
    <Modal v-model:visible="installVisible" title="节点部署命令">
      <p class="warn-big">请立即复制部署命令，token 仅显示这一次。</p>
      <CodeBox :text="installCmd" multiline />
      <p v-if="caFingerprint" class="muted ca-fp" :title="`完整指纹: ${caFingerprint}`">
        面板 CA 指纹: {{ caFingerprint.slice(0, 32) }}… (可在节点侧用 openssl x509 -in /etc/ksing/panel-ca.pem -outform der | sha256sum 比对)
      </p>
      <div class="row" style="margin-top: 12px; justify-content: flex-end">
        <CopyButton :text="installCmd" label="复制部署命令" />
      </div>
      <p class="muted" style="margin: 12px 0 0; font-size: 12.5px">
        在目标 VPS 上以 root 执行该命令即可完成接入，之后可在本页查看在线状态。
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
        <div class="kv" style="margin-bottom: 12px"><span class="k">关联规则集</span><span class="v">{{ cfg.rulesets.length ? cfg.rulesets.join(', ') : '无' }}</span></div>
        <CodeBox :text="cfgText" multiline />
      </template>
      <template #footer>
        <Button @click="cfgVisible = false">关闭</Button>
      </template>
    </Drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
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
  cert_mode: 'selfip' as 'acme' | 'selfip' | 'unsafe',
  domain: '',
  acme_email: '',
  unsafe_ok: false,
  users: [] as string[],
  note: '',
  enabled: true,
})

const installVisible = ref(false)
const installCmd = ref('')
const caFingerprint = ref('')

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

const routeVisible = ref(false)
const routeServer = ref<ServerItem>()

function openRoute(s: ServerItem) {
  routeServer.value = s
  routeVisible.value = true
}

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
  if (!s.cert_not_after) return 'muted'
  const now = Date.now() / 1000
  if (s.cert_not_after <= now) return 'exp-red'
  if ((s.cert_not_after - now) / 86400 < 10) return 'exp-yellow'
  return 'muted'
}

async function load() {
  loading.value = true
  try {
    const [sv, us] = await Promise.all([
      get<ServerItem[]>('/api/servers'),
      get<UserInfo[]>('/api/users'),
    ])
    servers.value = sv
    userNames.value = us.map((u) => u.name)
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

function openAdd() {
  editing.value = null
  Object.assign(form, {
    name: '',
    port: 18443,
    cert_mode: 'selfip',
    domain: '',
    acme_email: '',
    unsafe_ok: false,
    users: [],
    note: '',
    enabled: true,
  })
  editVisible.value = true
}

function openEdit(s: ServerItem) {
  editing.value = s
  Object.assign(form, {
    name: s.name,
    port: s.port,
    cert_mode: s.cert_mode || (s.domain ? 'acme' : 'selfip'),
    domain: s.domain,
    acme_email: s.acme_email,
    unsafe_ok: false,
    users: [...(s.users || [])],
    note: s.note,
    enabled: s.enabled,
  })
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
  if (form.cert_mode === 'acme' && !form.domain.trim()) {
    toast('acme 模式需要绑定域名', 'error')
    return
  }
  if (form.cert_mode === 'unsafe' && !form.unsafe_ok) {
    toast('请先勾选确认了解不安全模式的风险', 'error')
    return
  }
  const domain = form.cert_mode === 'acme' ? form.domain.trim() : ''
  const acmeEmail = form.cert_mode === 'acme' ? form.acme_email.trim() : ''
  saving.value = true
  try {
    if (editing.value) {
      const body: Record<string, unknown> = {
        name: form.name.trim(),
        port,
        users: form.users,
        note: form.note,
        enabled: form.enabled,
        cert_mode: form.cert_mode,
        domain,
        acme_email: acmeEmail,
      }
      if (form.cert_mode === 'unsafe') body.unsafe_ok = true
      await put(`/api/servers/${editing.value.sid}`, body)
      toast('节点已更新，已自动下发到相关节点', 'success')
      editVisible.value = false
    } else {
      const body: Record<string, unknown> = { name: form.name.trim(), port, cert_mode: form.cert_mode }
      if (domain) body.domain = domain
      if (acmeEmail) body.acme_email = acmeEmail
      if (form.cert_mode === 'unsafe') body.unsafe_ok = true
      if (form.users.length) body.users = form.users
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

async function resetToken(s: ServerItem) {
  if (!(await confirmDialog(`重置节点「${s.name}」的部署令牌？\n旧 token 立即失效，节点需重新部署。`))) return
  try {
    const r = await post<ServerCreated>(`/api/servers/${s.sid}/token`)
    showInstall(r.install_command)
  } catch (e) {
    toast((e as Error).message, 'error')
  }
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
  timer = setInterval(load, 20000)
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
  margin-right: 6px;
}

.dot.on {
  background: var(--c-green);
  box-shadow: 0 0 5px var(--c-green);
}

.fw {
  grid-column: 1 / -1;
}

.field-row {
  display: flex;
  align-items: flex-end;
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

.cert-tip {
  align-self: end;
  margin: 0;
  font-size: 12.5px;
  padding-bottom: 8px;
}
</style>
