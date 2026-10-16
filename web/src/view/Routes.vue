<template>
  <div class="page">
    <div class="page-head">
      <h2>分流规则</h2>
      <div class="spacer"></div>
      <Button variant="primary" @click="openAdd()">添加规则</Button>
    </div>
    <p class="page-sub">规则按顺序匹配，越靠前优先级越高；未命中规则的流量走默认出口。</p>

    <div class="grid2">
      <div class="card">
        <h3 class="card-title">全局默认出口</h3>
        <div class="row">
          <span class="muted">当前生效:</span>
          <Badge :color="data.effective_final === 'reject' ? 'red' : data.effective_final === 'direct' ? 'dim' : 'cyan'">
            {{ data.effective_final }}
          </Badge>
          <Badge v-if="!data.final" color="dim">继承设置</Badge>
        </div>
        <div class="row" style="margin-top: 12px">
          <Select v-model="finalPick" :options="outboundOptions" style="flex: 1" />
          <Button small variant="primary" :loading="finalSaving" @click="saveFinal()">保存</Button>
          <Button v-if="data.final" small :loading="finalSaving" @click="clearFinal()">恢复默认</Button>
        </div>
      </div>

      <div class="card">
        <h3 class="card-title">用户专属出口</h3>
        <Empty v-if="!userFinalEntries.length" text="无专属出口，用户走全局默认" />
        <div v-for="[u, o] in userFinalEntries" :key="u" class="uf-row">
          <Badge color="green">{{ u }}</Badge>
          <span class="muted">→</span>
          <Badge :color="o === 'reject' ? 'red' : o === 'direct' ? 'dim' : 'cyan'">{{ o }}</Badge>
          <div class="spacer"></div>
          <Button small variant="danger" @click="delUserFinal(u)">删除</Button>
        </div>
        <div class="row" style="margin-top: 12px">
          <Select v-model="ufUser" :options="availableUsers" style="flex: 1" />
          <Select v-model="ufOutbound" :options="outboundOptions" style="flex: 1" />
          <Button small variant="primary" :loading="finalSaving" @click="addUserFinal">添加</Button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3 class="card-title">规则列表<span class="sub">{{ data.rules.length }} 条</span></h3>
      <Spinner v-if="loading" />
      <Empty v-else-if="!data.rules.length" text="暂无规则，全部流量走默认出口">
        <Button small variant="primary" @click="openAdd()">添加第一条规则</Button>
      </Empty>
      <div v-else class="rule-list">
        <div v-for="(r, i) in data.rules" :key="i" class="rule-card">
          <span class="idx mono muted">{{ i + 1 }}</span>
          <div class="rule-cond">
            <span v-for="s in r.rule_set" :key="'s' + s" class="chip purple">{{ s }}</span>
            <span v-for="u in r.users" :key="'u' + u" class="chip green">👤 {{ u }}</span>
            <span v-for="n in r.nodes" :key="'n' + n" class="chip">⛁ {{ serverName(n) }}</span>
            <span v-for="t in condText(r)" :key="t" class="chip">{{ t }}</span>
          </div>
          <Badge v-if="r.action === 'reject'" color="red">拒绝</Badge>
          <Badge v-else :color="r.outbound === 'direct' ? 'dim' : 'cyan'">{{ r.outbound }}</Badge>
          <Badge v-if="r.dns" color="purple">dns:{{ r.dns }}</Badge>
          <div class="row rule-acts">
            <Button small :disabled="i === 0" title="上移" @click="move(i, -1)">↑</Button>
            <Button small :disabled="i === data.rules.length - 1" title="下移" @click="move(i, 1)">↓</Button>
            <Button small variant="danger" @click="delRule(i)">删除</Button>
          </div>
        </div>
      </div>
    </div>

    <!-- 添加规则 -->
    <Drawer v-model:visible="addVisible" title="添加规则" width="500px">
      <p class="muted" style="margin: 0 0 14px; font-size: 12.5px">
        各条件之间为「与」关系，至少需要一个匹配条件（规则集/域名/IP/端口）。规则追加到列表末尾。
      </p>

      <div class="form-grid">
        <div class="fw">
          <span class="lbl">规则集</span>
          <div v-if="form.rule_set.length" style="margin-bottom: 6px">
            <span v-for="s in form.rule_set" :key="s" class="chip purple">
              {{ s }}
              <b class="x" @click="form.rule_set = form.rule_set.filter((x) => x !== s)">×</b>
            </span>
          </div>
          <input v-model="setSearch" class="rs-input" placeholder="搜索规则集，如 geosite-cn" @input="searchSets" />
          <div v-if="setResults.length" class="rs-list">
            <div
              v-for="r in setResults"
              :key="r.tag"
              class="rs-item"
              :title="r.downloaded ? '已下载' : '未下载, 点击自动下载'"
              @click="pickSet(r)"
            >
              <span class="mono">{{ r.tag }}</span>
              <Badge color="dim">{{ r.source }}</Badge>
              <Badge :color="r.downloaded ? 'green' : 'yellow'">{{ r.downloaded ? '已下载' : '未下载' }}</Badge>
            </div>
          </div>
          <div v-else-if="setSearch.trim() && !setSearching" class="rs-empty">
            <span class="muted">无匹配规则集</span>
            <Button v-if="!setIndexed" small :loading="setBuilding" @click="buildSetIndex">构建规则集清单</Button>
          </div>
        </div>

        <Input v-model="form.domain" label="域名" hint="逗号分隔" placeholder="example.com, google.com" />
        <Input v-model="form.domain_suffix" label="域名后缀" hint="逗号分隔" placeholder="google.com, youtube.com" />
        <Input v-model="form.domain_keyword" label="域名关键字" hint="逗号分隔" placeholder="google" />
        <Input v-model="form.domain_regex" label="域名正则" hint="逗号分隔" placeholder="^.*\.google\..*$" />
        <Input v-model="form.ip_cidr" label="IP CIDR" hint="逗号分隔" placeholder="91.108.0.0/16" />
        <Input v-model="form.port" label="端口" hint="逗号分隔数字" placeholder="80, 443" />

        <div class="fw2">
          <MultiSelect v-model="form.users" :options="userNames" label="生效用户" hint="不选 = 所有用户" />
        </div>

        <div class="fw2">
          <MultiSelect v-model="form.nodes" :options="serverOptions" label="生效节点" hint="不选 = 所有节点" />
        </div>

        <Select v-model="form.action" label="动作" :options="[
          { label: 'route 转发到出站', value: 'route' },
          { label: 'reject 拒绝', value: 'reject' },
        ]" />
        <Select v-if="form.action === 'route'" v-model="form.outbound" label="出站" :options="directAndNodes" />
        <Select v-model="form.dns" label="DNS 分流" :options="[
          { label: '无', value: '' },
          { label: 'remote (1.1.1.1)', value: 'remote' },
          { label: 'remote-us (8.8.8.8)', value: 'remote-us' },
        ]" />
      </div>

      <template #footer>
        <Button @click="addVisible = false">取消</Button>
        <Button variant="primary" :loading="saving" @click="saveRule">添加</Button>
      </template>
    </Drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Drawer from '@/component/ui/Drawer.vue'
import Empty from '@/component/ui/Empty.vue'
import Input from '@/component/ui/Input.vue'
import MultiSelect from '@/component/ui/MultiSelect.vue'
import Select from '@/component/ui/Select.vue'
import Spinner from '@/component/ui/Spinner.vue'
import { del as httpDel, get, post } from '@/util/request'
import { confirmDialog } from '@/util/confirm'
import { toast } from '@/util/toast'
import type { NodeInfo, RouteRule, RoutesData, RulesetItem, ServerItem, UserInfo } from '@/types'

const route = useRoute()

const data = ref<RoutesData>({ rules: [], final: null, user_final: {}, effective_final: 'direct' })
const nodes = ref<Record<string, NodeInfo>>({})
const servers = ref<ServerItem[]>([])
const userNames = ref<string[]>([])
const loading = ref(true)
const saving = ref(false)
const finalSaving = ref(false)
const finalPick = ref('direct')
const ufUser = ref('')
const ufOutbound = ref('direct')

const addVisible = ref(false)
const setSearch = ref('')
const setResults = ref<RulesetItem[]>([])
const setSearching = ref(false)
const setIndexed = ref(true)
const setBuilding = ref(false)
const form = reactive({
  rule_set: [] as string[],
  domain: '',
  domain_suffix: '',
  domain_keyword: '',
  domain_regex: '',
  ip_cidr: '',
  port: '',
  users: [] as string[],
  nodes: [] as string[],
  action: 'route' as 'route' | 'reject',
  outbound: 'direct',
  dns: '',
})

const serverOptions = computed(() =>
  servers.value.map((s) => ({ label: `${s.name} (${s.sid})`, value: s.sid })),
)

function serverName(sid: string): string {
  return servers.value.find((s) => s.sid === sid)?.name ?? sid
}

const outboundOptions = computed(() => [
  { label: 'direct 直连', value: 'direct' },
  { label: 'reject 拒绝', value: 'reject' },
  ...Object.keys(nodes.value).sort().map((t) => ({ label: `节点: ${t}`, value: t })),
])

const directAndNodes = computed(() => [
  { label: 'direct 直连', value: 'direct' },
  ...Object.keys(nodes.value).sort().map((t) => ({ label: `节点: ${t}`, value: t })),
])

const userFinalEntries = computed(() => Object.entries(data.value.user_final).sort())

const availableUsers = computed(() => {
  const used = new Set(Object.keys(data.value.user_final))
  const list = userNames.value.filter((u) => !used.has(u))
  return list.length ? list : ['（无可用用户）']
})

let searchTimer: ReturnType<typeof setTimeout> | undefined

function condText(r: RouteRule): string[] {
  const out: string[] = []
  const push = (label: string, vals?: Array<string | number>) => {
    if (vals?.length) out.push(`${label}: ${vals.join(', ')}`)
  }
  push('domain', r.domain)
  push('suffix', r.domain_suffix)
  push('keyword', r.domain_keyword)
  push('regex', r.domain_regex)
  push('ip', r.ip_cidr)
  push('port', r.port)
  return out
}

async function load() {
  loading.value = true
  try {
    const [rc, nd, sv, us] = await Promise.all([
      get<RoutesData>('/api/routes'),
      get<Record<string, NodeInfo>>('/api/nodes'),
      get<ServerItem[]>('/api/servers'),
      get<UserInfo[]>('/api/users'),
    ])
    data.value = rc
    nodes.value = nd
    servers.value = sv
    userNames.value = us.map((u) => u.name)
    finalPick.value = rc.final || rc.effective_final
    const avail = userNames.value.filter((u) => !(u in rc.user_final))
    ufUser.value = avail[0] || ''
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

async function saveFinal() {
  finalSaving.value = true
  try {
    await post('/api/routes/final', { outbound: finalPick.value })
    toast('默认出口已保存', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    finalSaving.value = false
  }
}

async function clearFinal() {
  finalSaving.value = true
  try {
    await httpDel('/api/routes/final', {})
    toast('已恢复为设置中的默认出口', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    finalSaving.value = false
  }
}

async function addUserFinal() {
  if (!availableUsers.value.includes(ufUser.value)) {
    toast('请选择用户', 'error')
    return
  }
  finalSaving.value = true
  try {
    await post('/api/routes/final', { outbound: ufOutbound.value, user: ufUser.value })
    toast('专属出口已添加', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    finalSaving.value = false
  }
}

async function delUserFinal(user: string) {
  if (!(await confirmDialog(`删除用户「${user}」的专属出口？`))) return
  try {
    await httpDel('/api/routes/final', { user })
    toast('已删除', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

async function move(index: number, dir: -1 | 1) {
  try {
    await post('/api/routes/move', { index, dir })
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

async function delRule(index: number) {
  if (!(await confirmDialog(`确定删除第 ${index + 1} 条规则？`))) return
  try {
    await httpDel(`/api/routes/${index}`)
    toast('已删除', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

function openAdd(preset?: string) {
  Object.assign(form, {
    rule_set: preset ? [preset] : [],
    domain: '',
    domain_suffix: '',
    domain_keyword: '',
    domain_regex: '',
    ip_cidr: '',
    port: '',
    users: [],
    nodes: [],
    action: 'route',
    outbound: 'direct',
    dns: '',
  })
  setSearch.value = ''
  setResults.value = []
  addVisible.value = true
}

function searchSets() {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(async () => {
    const q = setSearch.value.trim()
    if (!q) {
      setResults.value = []
      return
    }
    setSearching.value = true
    try {
      const r = await get<{ results: RulesetItem[]; indexed: boolean }>(`/api/rulesets?q=${encodeURIComponent(q)}`)
      setIndexed.value = r.indexed
      setResults.value = r.results.filter((x) => !form.rule_set.includes(x.tag)).slice(0, 20)
    } catch {
      /* 搜索失败静默 */
    } finally {
      setSearching.value = false
    }
  }, 250)
}

async function buildSetIndex() {
  setBuilding.value = true
  try {
    await post('/api/rulesets/index', {})
    toast('规则集清单已构建', 'success')
    setIndexed.value = true
    searchSets()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    setBuilding.value = false
  }
}

async function pickSet(r: RulesetItem) {
  if (!r.downloaded) {
    // 未下载: 自动下载后再选中
    toast(`正在下载 ${r.tag} …`)
    try {
      const res = await post<{ ok: string[]; fail: Record<string, string> }>('/api/rulesets/download', { tags: [r.tag] })
      if (res.fail && res.fail[r.tag]) {
        toast(`下载失败: ${res.fail[r.tag]}`, 'error')
        return
      }
      toast(`${r.tag} 已下载`, 'success')
    } catch (e) {
      toast((e as Error).message, 'error')
      return
    }
  }
  if (!form.rule_set.includes(r.tag)) form.rule_set = [...form.rule_set, r.tag]
  setResults.value = setResults.value.filter((x) => x.tag !== r.tag)
}

function splitCsv(text: string): string[] {
  return text.split(/[,，\n]/).map((s) => s.trim()).filter(Boolean)
}

async function saveRule() {
  const body: Record<string, unknown> = {}
  if (form.rule_set.length) body.rule_set = form.rule_set
  for (const k of ['domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr'] as const) {
    const vals = splitCsv(form[k])
    if (vals.length) body[k] = vals
  }
  if (form.port.trim()) {
    const ports = splitCsv(form.port).map(Number)
    if (ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) {
      toast('端口格式错误', 'error')
      return
    }
    body.port = ports
  }
  if (!Object.keys(body).length) {
    toast('至少需要一个匹配条件（规则集/域名/IP/端口）', 'error')
    return
  }
  if (form.users.length) body.users = form.users
  if (form.nodes.length) body.nodes = form.nodes
  body.action = form.action
  if (form.action === 'route') body.outbound = form.outbound
  if (form.dns) body.dns = form.dns

  saving.value = true
  try {
    await post('/api/routes', body)
    toast('规则已添加，已自动下发到相关节点', 'success')
    addVisible.value = false
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

onMounted(async () => {
  await load()
  const preset = route.query.set
  if (typeof preset === 'string' && preset) openAdd(preset)
})
</script>

<style scoped>
.grid2 {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px;
  margin-bottom: 16px;
}

.uf-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 0;
  border-bottom: 1px dashed var(--c-border);
}

.rule-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.rule-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid var(--c-border);
  border-radius: var(--r-md);
  background: var(--c-inset);
  transition: border-color 0.15s var(--ease);
  flex-wrap: wrap;
}

.rule-card:hover {
  border-color: var(--c-border-strong);
}

.idx {
  width: 22px;
  text-align: right;
  flex-shrink: 0;
}

.rule-cond {
  flex: 1;
  min-width: 200px;
  white-space: normal;
}

.rule-acts {
  gap: 6px;
  flex-shrink: 0;
}

.fw {
  grid-column: 1 / -1;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.fw2 {
  grid-column: span 1;
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

.lbl {
  font-size: 12.5px;
  color: var(--c-text-dim);
  font-weight: 500;
}

.rs-input {
  width: 100%;
  padding: 9px 12px;
  border-radius: 10px;
  border: 1px solid var(--c-border);
  background: var(--c-inset);
  color: var(--c-text);
  font-size: 13.5px;
  font-family: var(--font);
  outline: none;
  transition: border-color 0.15s var(--ease), box-shadow 0.15s var(--ease);
}

.rs-input:focus {
  border-color: var(--c-primary);
  box-shadow: 0 0 0 3px var(--c-primary-soft);
}

.rs-list {
  border: 1px solid var(--c-border);
  border-radius: 10px;
  background: var(--c-inset);
  max-height: 180px;
  overflow-y: auto;
}

.rs-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 12px;
  cursor: pointer;
  font-size: 12.5px;
  transition: background-color 0.12s var(--ease);
}

.rs-item:hover {
  background: var(--c-primary-soft);
}

.rs-empty {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
  font-size: 12.5px;
}
</style>
