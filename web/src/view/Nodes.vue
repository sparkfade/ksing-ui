<template>
  <div class="page">
    <div class="page-head">
      <h2>出站节点</h2>
      <div class="spacer"></div>
      <Button @click="importVisible = true">批量导入</Button>
      <Button :loading="testingAll" @click="testAll">全部测试</Button>
      <Button variant="primary" @click="openAdd">添加节点</Button>
    </div>
    <p class="page-sub">出站节点（Shadowsocks / AnyTLS），供分流规则与默认出口选择；改动实时下发到各服务器节点。</p>

    <div class="card">
      <Spinner v-if="loading" />
      <Empty v-else-if="!tags.length" text="暂无出站节点">
        <Button small variant="primary" @click="openAdd">添加第一个出站</Button>
      </Empty>
      <div v-else class="table-wrap">
        <table class="tbl">
          <thead>
            <tr>
              <th>标签</th>
              <th>地址</th>
              <th>类型</th>
              <th>SNI / 加密</th>
              <th>UDP over TCP</th>
              <th>证书验证</th>
              <th>状态</th>
              <th style="width: 190px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="tag in tags" :key="tag">
              <td><Badge>{{ tag }}</Badge></td>
              <td class="mono">{{ nodes[tag].server }}:{{ nodes[tag].server_port }}</td>
              <td><Badge :color="nodes[tag].type === 'anytls' ? 'cyan' : 'dim'">{{ nodes[tag].type === 'anytls' ? 'AnyTLS' : 'SS' }}</Badge></td>
              <td class="mono">{{ nodes[tag].type === 'anytls' ? (nodes[tag].sni || nodes[tag].server) : nodes[tag].method }}</td>
              <td>
                <template v-if="nodes[tag].type !== 'anytls'">
                  <Badge :color="nodes[tag].udp_over_tcp ? 'green' : 'dim'">{{ nodes[tag].udp_over_tcp ? '开启' : '关闭' }}</Badge>
                </template>
                <span v-else class="muted">-</span>
              </td>
              <td>
                <template v-if="nodes[tag].type === 'anytls'">
                  <Badge :color="nodes[tag].insecure ? 'red' : 'green'">{{ nodes[tag].insecure ? '跳过' : '验证' }}</Badge>
                </template>
                <span v-else class="muted">-</span>
              </td>
              <td>
                <template v-if="tests[tag]">
                  <span v-if="tests[tag].loading" class="muted">测试中…</span>
                  <span v-else-if="tests[tag].ok" class="test-ok" :title="tests[tag].detail || ''">
                    ✓ {{ tests[tag].latency_ms }}ms<span v-if="tests[tag].mode === 'tcp'" class="test-weak"> (探活)</span>
                  </span>
                  <span v-else class="test-fail" :title="tests[tag].error">✗ 失败</span>
                </template>
                <span v-else class="muted">-</span>
              </td>
              <td>
                <div class="row">
                  <Button small :loading="tests[tag]?.loading" @click="testNode(tag)">测试</Button>
                  <Button small @click="openEdit(tag)">编辑</Button>
                  <Button small variant="danger" @click="del(tag)">删除</Button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- 添加 / 编辑节点 -->
    <Drawer v-model:visible="editVisible" :title="editing ? `编辑节点: ${editing}` : '添加节点'">
      <!-- 链接一键解析 (仅添加模式): 参考 3x-ui, 粘贴分享链接自动填表 -->
      <div v-if="!editing" class="parse-box">
        <div class="parse-title">从分享链接导入</div>
        <div class="parse-row">
          <input
            v-model="parseLink"
            class="ctrl parse-input"
            placeholder="粘贴 ss:// 或 anytls:// 链接"
            autocomplete="off"
            @keydown.enter.prevent="doParse"
          />
          <Button :loading="parsing" @click="doParse">解析</Button>
        </div>
        <p class="parse-hint">解析后自动填充下方表单，可继续手动修改</p>
      </div>
      <div class="form-grid">
        <Select v-if="!editing" v-model="form.type" label="类型" :options="TYPE_OPTIONS" />
        <Input v-model="form.tag" label="标签" placeholder="唯一标识，如 hk-01" />
        <Input v-model="form.server" label="服务器地址" placeholder="example.com" />
        <Input v-model.number="form.server_port" label="端口" type="number" placeholder="443" />
        <template v-if="form.type === 'anytls'">
          <Input v-model="form.password" label="密码" placeholder="AnyTLS 密码" />
          <Input v-model="form.sni" label="SNI" hint="留空 = 使用服务器地址" placeholder="example.com" />
          <div class="field-row">
            <Toggle v-model="form.insecure" label="跳过证书验证 (insecure)" />
          </div>
        </template>
        <template v-else>
          <Select v-model="form.method" label="加密方式" :options="SS_METHODS" />
          <Input
            v-model="form.password"
            :label="form.method.startsWith('2022-blake3-') ? '密钥' : '密码'"
            :hint="form.method.startsWith('2022-blake3-') ? 'Base64 编码的 16 字节（128 位）或 32 字节（256 位）密钥' : ''"
            placeholder="节点密码 / 密钥"
          />
          <Select v-model="form.plugin" label="插件 (可选)" :options="SS_PLUGINS" />
          <Input v-model="form.plugin_opts" label="插件参数 (可选)" placeholder="obfs=http;obfs-host=example.com" />
          <div class="field-row">
            <Toggle v-model="form.udp_over_tcp" label="UDP over TCP" />
          </div>
        </template>
      </div>
      <template #footer>
        <Button @click="editVisible = false">取消</Button>
        <Button variant="primary" :loading="saving" @click="save">保存</Button>
      </template>
    </Drawer>

    <!-- 批量导入 -->
    <Drawer v-model:visible="importVisible" title="批量导入分享链接">
      <Input
        v-model="importText"
        label="ss:// 或 anytls:// 链接"
        hint="每行一条"
        textarea
        :rows="8"
        placeholder="ss://base64...#tag&#10;anytls://password@host:port?sni=xxx&insecure=1#tag"
      />
      <div style="margin-top: 12px">
        <Toggle v-model="importUot" label="UDP over TCP (仅 ss)" />
      </div>
      <div v-if="importResults.length" class="results">
        <div v-for="r in importResults" :key="r.tag" class="result-row">
          <Badge :color="r.ok ? 'green' : 'red'">{{ r.ok ? '成功' : '失败' }}</Badge>
          <span class="mono">{{ r.tag }}</span>
          <span class="muted">{{ r.ok ? r.server : r.error }}</span>
        </div>
      </div>
      <template #footer>
        <Button @click="importVisible = false">关闭</Button>
        <Button variant="primary" :loading="importing" @click="doImport">导入</Button>
      </template>
    </Drawer>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Drawer from '@/component/ui/Drawer.vue'
import Empty from '@/component/ui/Empty.vue'
import Input from '@/component/ui/Input.vue'
import Select from '@/component/ui/Select.vue'
import Spinner from '@/component/ui/Spinner.vue'
import Toggle from '@/component/ui/Toggle.vue'
import { del as httpDel, get, post, put } from '@/util/request'
import { confirmDialog } from '@/util/confirm'
import { toast } from '@/util/toast'
import { SS_METHODS, type NodeInfo } from '@/types'

const nodes = ref<Record<string, NodeInfo>>({})
const loading = ref(true)
const tags = computed(() => Object.keys(nodes.value).sort())

const editVisible = ref(false)
const editing = ref('')
const saving = ref(false)
const TYPE_OPTIONS = [
  { label: 'Shadowsocks', value: 'ss' },
  { label: 'AnyTLS (anytls:// 链接)', value: 'anytls' },
]
const SS_PLUGINS = [
  { label: '不使用插件', value: '' },
  { label: 'obfs-local', value: 'obfs-local' },
  { label: 'v2ray-plugin', value: 'v2ray-plugin' },
]
const form = reactive({
  tag: '',
  type: 'ss' as 'ss' | 'anytls',
  server: '',
  server_port: 443,
  method: '2022-blake3-aes-128-gcm',
  password: '',
  udp_over_tcp: false,
  sni: '',
  insecure: false,
  plugin: '',
  plugin_opts: '',
})

const parseLink = ref('')
const parsing = ref(false)

async function doParse() {
  const link = parseLink.value.trim()
  if (!link) {
    toast('请粘贴 ss:// 或 anytls:// 链接', 'error')
    return
  }
  parsing.value = true
  try {
    const r = await post<{
      type: 'ss' | 'anytls'
      tag: string
      server: string
      server_port: number
      password: string
      method?: string
      plugin?: string
      plugin_opts?: string
      sni?: string
      insecure?: boolean
    }>('/api/nodes/parse', { link })
    form.type = r.type
    form.server = r.server
    form.server_port = r.server_port
    form.password = r.password
    form.tag = r.tag || form.tag
    if (r.type === 'anytls') {
      form.sni = r.sni || ''
      form.insecure = !!r.insecure
    } else {
      form.method = r.method || form.method
      form.plugin = r.plugin || ''
      form.plugin_opts = r.plugin_opts || ''
    }
    toast(r.type === 'anytls' ? '已解析 AnyTLS 链接' : '已解析 SS 链接', 'success')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    parsing.value = false
  }
}

const importVisible = ref(false)
const importText = ref('')
const importUot = ref(false)
const importing = ref(false)
const importResults = ref<Array<{ tag: string; ok: boolean; server?: string; error?: string }>>([])

async function load() {
  loading.value = true
  try {
    nodes.value = await get<Record<string, NodeInfo>>('/api/nodes')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

function openAdd() {
  editing.value = ''
  Object.assign(form, {
    tag: '',
    type: 'ss',
    server: '',
    server_port: 443,
    method: '2022-blake3-aes-128-gcm',
    password: '',
    udp_over_tcp: false,
    sni: '',
    insecure: false,
    plugin: '',
    plugin_opts: '',
  })
  parseLink.value = ''
  editVisible.value = true
}

function openEdit(tag: string) {
  const n = nodes.value[tag]
  editing.value = tag
  Object.assign(form, {
    tag,
    type: n.type === 'anytls' ? 'anytls' : 'ss',
    server: n.server,
    server_port: n.server_port,
    method: n.method || '2022-blake3-aes-128-gcm',
    password: n.password,
    udp_over_tcp: !!n.udp_over_tcp,
    sni: n.sni || '',
    insecure: !!n.insecure,
    plugin: n.plugin || '',
    plugin_opts: n.plugin_opts || '',
  })
  editVisible.value = true
}

async function save() {
  if (!form.tag.trim() || !form.server.trim() || !form.password) {
    toast('标签、地址、密码不能为空', 'error')
    return
  }
  saving.value = true
  try {
    const base: Record<string, unknown> =
      form.type === 'anytls'
        ? {
            type: 'anytls',
            server: form.server.trim(),
            server_port: Number(form.server_port),
            password: form.password,
            sni: form.sni.trim(),
            insecure: form.insecure,
          }
        : {
            server: form.server.trim(),
            server_port: Number(form.server_port),
            method: form.method,
            password: form.password,
            udp_over_tcp: form.udp_over_tcp,
            ...(form.plugin.trim()
              ? { plugin: form.plugin.trim(), plugin_opts: form.plugin_opts.trim() }
              : {}),
          }
    if (editing.value) {
      if (form.tag.trim() !== editing.value) base.new_tag = form.tag.trim()
      await put(`/api/nodes/${encodeURIComponent(editing.value)}`, base)
      toast('节点已更新', 'success')
    } else {
      await post('/api/nodes', { tag: form.tag.trim(), ...base })
      toast('节点已添加', 'success')
    }
    editVisible.value = false
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

async function del(tag: string) {
  if (!(await confirmDialog(`确定删除节点「${tag}」？`))) return
  try {
    await httpDel(`/api/nodes/${encodeURIComponent(tag)}`)
    toast('已删除', 'success')
    load()
  } catch (e) {
    toast((e as Error).message, 'error')
  }
}

// ---- 出站测活

interface TestResult {
  loading: boolean
  ok?: boolean
  latency_ms?: number
  mode?: string
  detail?: string
  error?: string
}

const tests = ref<Record<string, TestResult>>({})
const testingAll = ref(false)

async function testNode(tag: string) {
  tests.value = { ...tests.value, [tag]: { loading: true } }
  try {
    const r = await post<TestResult>(`/api/nodes/${encodeURIComponent(tag)}/test`, {})
    tests.value = {
      ...tests.value,
      [tag]: { ...r, loading: false },
    }
    if (r.ok) {
      toast(`${tag}: 可用, ${r.latency_ms}ms${r.mode === 'tcp' ? ' (仅探活)' : ''}`, 'success')
    } else {
      toast(`${tag}: ${r.error}`, 'error')
    }
  } catch (e) {
    tests.value = { ...tests.value, [tag]: { loading: false, ok: false, error: (e as Error).message } }
    toast((e as Error).message, 'error')
  }
}

async function testAll() {
  testingAll.value = true
  try {
    for (const tag of tags.value) await testNode(tag)
  } finally {
    testingAll.value = false
  }
}

async function doImport() {
  if (!importText.value.trim()) {
    toast('请粘贴 ss:// 或 anytls:// 链接', 'error')
    return
  }
  importing.value = true
  try {
    const r = await post<{ results: typeof importResults.value }>('/api/nodes/import', {
      text: importText.value,
      uot: importUot.value,
    })
    importResults.value = r.results
    const okCount = r.results.filter((x) => x.ok).length
    toast(`导入完成: ${okCount}/${r.results.length} 成功`, okCount ? 'success' : 'error')
    if (okCount) load()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    importing.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.parse-box {
  border: 1px dashed var(--c-border);
  border-radius: 10px;
  padding: 12px;
  margin-bottom: 14px;
  background: var(--c-inset);
}

.parse-title {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--c-text-dim);
  margin-bottom: 8px;
}

.parse-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.parse-input {
  flex: 1;
  min-width: 0;
  width: 100%;
  padding: 9px 12px;
  border-radius: 10px;
  border: 1px solid var(--c-border);
  background: var(--c-inset);
  color: var(--c-text);
  font-size: 12.5px;
  font-family: var(--font);
  outline: none;
  transition: border-color 0.15s var(--ease), box-shadow 0.15s var(--ease);
}

.parse-input::placeholder {
  color: var(--c-text-faint);
}

.parse-input:focus {
  border-color: var(--c-primary);
  box-shadow: 0 0 0 3px var(--c-primary-soft);
}

.parse-hint {
  margin: 8px 0 0;
  font-size: 12px;
  color: var(--c-text-dim);
  opacity: 0.8;
}

.field-row {
  display: flex;
  align-items: flex-end;
  padding-bottom: 8px;
}

.results {
  margin-top: 14px;
  border-top: 1px dashed var(--c-border);
  padding-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.result-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
}

.test-ok {
  color: var(--c-green);
  font-size: 12.5px;
  font-weight: 500;
  cursor: default;
}

.test-fail {
  color: var(--c-red);
  font-size: 12.5px;
  font-weight: 500;
  cursor: help;
}

.test-weak {
  opacity: 0.7;
  font-size: 11px;
}
</style>
