<template>
  <div>
    <Spinner v-if="loading" />
    <Empty v-else-if="!scopedRules.length" text="暂无专属规则" />
    <div v-else class="rule-list">
      <div v-for="{ rule: r, index } in scopedRules" :key="index" class="rule-row">
        <div class="rule-cond">
          <span v-for="s in r.rule_set" :key="'s' + s" class="chip purple">{{ s }}</span>
          <span v-for="u in r.users" :key="'u' + u" class="chip green">{{ u }}</span>
          <span v-for="n in r.nodes" :key="'n' + n" class="chip">⛁ {{ serverName(n) }}</span>
          <span v-for="t in condText(r)" :key="t" class="chip">{{ t }}</span>
          <span v-if="!r.rule_set?.length && !condText(r).length" class="muted">全部流量</span>
        </div>
        <Badge v-if="r.action === 'reject'" color="red">拒绝</Badge>
        <Badge v-else :color="r.outbound === 'direct' ? 'dim' : 'cyan'">{{ r.outbound }}</Badge>
        <Button small variant="danger" @click="delRule(index)">删除</Button>
      </div>
    </div>

    <h4 class="add-title">添加规则</h4>
    <div class="form-grid">
      <div class="fw">
        <span class="lbl">规则集<i class="hint">搜索选择；未下载项点击后自动下载</i></span>
        <div v-if="form.rule_set.length" style="margin-bottom: 6px">
          <span v-for="s in form.rule_set" :key="s" class="chip purple">
            {{ s }}
            <b class="x" @click="form.rule_set = form.rule_set.filter((x) => x !== s)">×</b>
          </span>
        </div>
        <input v-model="setSearch" class="rs-input" placeholder="搜索规则集，如 geosite-cn" @input="searchSets" />
        <div v-if="setResults.length" class="rs-list">
          <div v-for="r in setResults" :key="r.tag" class="rs-item" @click="pickSet(r)">
            <span class="mono">{{ r.tag }}</span>
            <span class="row" style="gap: 6px">
              <Badge v-if="downloading === r.tag" color="yellow">下载中…</Badge>
              <Badge v-else-if="r.downloaded === false" color="yellow">未下载</Badge>
              <Badge color="dim">{{ r.source }}</Badge>
            </span>
          </div>
        </div>
      </div>
      <Input v-model="form.domain" label="域名" hint="逗号分隔" placeholder="example.com, google.com" />
      <Input v-model="form.domain_suffix" label="域名后缀" hint="逗号分隔" placeholder="google.com" />
      <Input v-model="form.domain_keyword" label="域名关键字" hint="逗号分隔" placeholder="google" />
      <Input v-model="form.domain_regex" label="域名正则" hint="逗号分隔" placeholder="^.*\.google\..*$" />
      <Input v-model="form.ip_cidr" label="IP CIDR" hint="逗号分隔" placeholder="91.108.0.0/16" />
      <Input v-model="form.port" label="端口" hint="逗号分隔数字" placeholder="80, 443" />
      <Select v-model="form.outbound" label="出站" :options="outboundOptions" :disabled="form.reject" />
      <div class="field-row">
        <Toggle v-model="form.reject" label="拒绝该流量 (reject)" />
      </div>
    </div>
    <div class="row" style="margin-top: 14px; justify-content: flex-end">
      <Button variant="primary" :loading="saving" @click="addRule">添加规则</Button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Empty from '@/component/ui/Empty.vue'
import Input from '@/component/ui/Input.vue'
import Select from '@/component/ui/Select.vue'
import Spinner from '@/component/ui/Spinner.vue'
import Toggle from '@/component/ui/Toggle.vue'
import { del as httpDel, get, post } from '@/util/request'
import { confirmDialog } from '@/util/confirm'
import { toast } from '@/util/toast'
import type { NodeInfo, RouteRule, RoutesData, RulesetItem, ServerItem } from '@/types'

const props = defineProps<{
  nodeSid?: string
  userName?: string
}>()

const rules = ref<RouteRule[]>([])
const nodeTags = ref<string[]>([])
const servers = ref<ServerItem[]>([])
const loading = ref(true)
const saving = ref(false)
const setSearch = ref('')
const setResults = ref<RulesetItem[]>([])
const downloading = ref('')
let searchTimer: ReturnType<typeof setTimeout> | undefined

const form = reactive({
  rule_set: [] as string[],
  domain: '',
  domain_suffix: '',
  domain_keyword: '',
  domain_regex: '',
  ip_cidr: '',
  port: '',
  outbound: 'direct',
  reject: false,
})

const scopedRules = computed(() =>
  rules.value
    .map((rule, index) => ({ rule, index }))
    .filter(({ rule }) => {
      if (props.nodeSid) return rule.nodes?.includes(props.nodeSid) && !rule.users?.length
      if (props.userName) return rule.users?.includes(props.userName)
      return false
    }),
)

const outboundOptions = computed(() => [
  { label: 'direct 直连', value: 'direct' },
  ...nodeTags.value.map((t) => ({ label: `节点: ${t}`, value: t })),
])

function serverName(sid: string): string {
  return servers.value.find((s) => s.sid === sid)?.name ?? sid
}

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
    const [rc, nd, sv] = await Promise.all([
      get<RoutesData>('/api/routes'),
      get<Record<string, NodeInfo>>('/api/nodes'),
      get<ServerItem[]>('/api/servers'),
    ])
    rules.value = rc.rules
    nodeTags.value = Object.keys(nd).sort()
    servers.value = sv
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

function searchSets() {
  clearTimeout(searchTimer)
  searchTimer = setTimeout(async () => {
    const q = setSearch.value.trim()
    if (!q) {
      setResults.value = []
      return
    }
    try {
      const r = await get<{ results: RulesetItem[] }>(`/api/rulesets?q=${encodeURIComponent(q)}`)
      setResults.value = r.results.filter((x) => !form.rule_set.includes(x.tag)).slice(0, 20)
    } catch {
      /* 搜索失败静默 */
    }
  }, 250)
}

async function pickSet(r: RulesetItem) {
  if (downloading.value) return
  if (r.downloaded === false) {
    downloading.value = r.tag
    try {
      const res = await post<{ ok: string[]; fail: Record<string, string> }>('/api/rulesets/download', { tags: [r.tag] })
      if (res.fail && res.fail[r.tag]) {
        toast(`下载失败: ${res.fail[r.tag]}`, 'error')
        return
      }
      toast(`规则集 ${r.tag} 已下载`, 'success')
    } catch (e) {
      toast((e as Error).message, 'error')
      return
    } finally {
      downloading.value = ''
    }
  }
  if (!form.rule_set.includes(r.tag)) form.rule_set = [...form.rule_set, r.tag]
  setResults.value = setResults.value.filter((x) => x.tag !== r.tag)
}

function splitCsv(text: string): string[] {
  return text.split(/[,，\n]/).map((s) => s.trim()).filter(Boolean)
}

async function addRule() {
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
  if (props.userName) body.users = [props.userName]
  if (props.nodeSid) body.nodes = [props.nodeSid]
  if (form.reject) body.action = 'reject'
  else body.outbound = form.outbound

  saving.value = true
  try {
    await post('/api/routes', body)
    toast('规则已添加，等待节点同步', 'success')
    Object.assign(form, {
      rule_set: [],
      domain: '',
      domain_suffix: '',
      domain_keyword: '',
      domain_regex: '',
      ip_cidr: '',
      port: '',
      outbound: 'direct',
      reject: false,
    })
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

async function delRule(index: number) {
  if (!(await confirmDialog(`确定删除第 ${index + 1} 条规则？`))) return
  try {
    await httpDel(`/api/routes/${index}`)
    toast('已删除，等待节点同步', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

onMounted(load)
</script>

<style scoped>
.rule-list {
  margin-bottom: 4px;
}

.rule-row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 0;
  border-bottom: 1px dashed var(--c-border);
}

.rule-cond {
  flex: 1;
  min-width: 0;
  white-space: normal;
}

.add-title {
  margin: 18px 0 12px;
  font-size: 13.5px;
  color: var(--c-text-dim);
  border-top: 1px solid var(--c-border);
  padding-top: 16px;
}

.fw {
  grid-column: 1 / -1;
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.lbl {
  font-size: 12.5px;
  color: var(--c-text-dim);
  font-weight: 500;
}

.hint {
  font-style: normal;
  margin-left: 6px;
  opacity: 0.75;
  font-weight: 400;
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
  flex-wrap: wrap;
  padding: 8px 12px;
  cursor: pointer;
  font-size: 12.5px;
  transition: background-color 0.12s var(--ease);
}

.rs-item > .mono {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}

.rs-item:hover {
  background: var(--c-primary-soft);
}

.field-row {
  display: flex;
  align-items: flex-end;
  padding-bottom: 8px;
}
</style>
