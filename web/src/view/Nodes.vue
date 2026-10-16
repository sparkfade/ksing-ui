<template>
  <div class="page">
    <div class="page-head">
      <h2>出站节点</h2>
      <div class="spacer"></div>
      <Button @click="importVisible = true">批量导入</Button>
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
              <th style="width: 130px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="tag in tags" :key="tag">
              <td><Badge>{{ tag }}</Badge></td>
              <td class="mono">{{ nodes[tag].server }}:{{ nodes[tag].server_port }}</td>
              <td><Badge :color="nodes[tag].type === 'anytls' ? 'cyan' : 'dim'">{{ nodes[tag].type === 'anytls' ? 'AnyTLS' : 'SS' }}</Badge></td>
              <td class="mono">{{ nodes[tag].type === 'anytls' ? (nodes[tag].sni || nodes[tag].server) : nodes[tag].method }}</td>
              <td>
                <Badge v-if="nodes[tag].type === 'anytls'" :color="nodes[tag].insecure ? 'red' : 'green'">{{ nodes[tag].insecure ? '跳过证书验证' : '验证证书' }}</Badge>
                <Badge v-else :color="nodes[tag].udp_over_tcp ? 'green' : 'dim'">{{ nodes[tag].udp_over_tcp ? '开启' : '关闭' }}</Badge>
              </td>
              <td>
                <div class="row">
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
          <Input v-model="form.password" label="密码" placeholder="节点密码" />
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
})

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
  })
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
            password: form.password.trim(),
            sni: form.sni.trim(),
            insecure: form.insecure,
          }
        : {
            server: form.server.trim(),
            server_port: Number(form.server_port),
            method: form.method,
            password: form.password,
            udp_over_tcp: form.udp_over_tcp,
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
</style>
