<template>
  <div class="page">
    <div class="page-head">
      <h2>设置</h2>
      <div class="spacer"></div>
      <Button small @click="load" :loading="loading">重置</Button>
      <Button variant="primary" :loading="saving" :disabled="loading" @click="save">保存设置</Button>
    </div>
    <p class="page-sub">设置变更保存后自动下发到相关节点；面板监听与端口修改需重启面板进程生效。</p>

    <Spinner v-if="loading" />

    <template v-else>
      <div class="card">
        <h3 class="card-title">代理服务</h3>
        <div class="form-grid">
          <Input v-model="form.sni" label="全局 SNI (可选)" hint="仅自签 / IP 证书模式的节点使用；域名证书节点的 SNI 即其域名" placeholder="www.apple.com" />
          <Select v-model="form.final" label="默认出站" hint="分流规则未命中时使用的出站" :options="finalOptions" />
          <Select v-model="form.private_action" label="私网地址处理" hint="目标为私网地址时如何处理" :options="[
            { label: 'reject 拒绝', value: 'reject' },
            { label: 'direct 直连', value: 'direct' },
            { label: 'off 不处理', value: 'off' },
          ]" />
          <Select v-model="form.log_level" label="日志级别" :options="LOG_LEVELS" />
          <div class="field-row">
            <Toggle v-model="form.auto_detect_interface" label="自动检测出口网卡" />
          </div>
        </div>
      </div>

      <div class="card">
        <h3 class="card-title">面板服务</h3>
        <div class="form-grid">
          <Input v-model="form.panel_listen" label="监听地址" hint=":: 全地址 / 127.0.0.1 仅本机" placeholder=":: / 127.0.0.1" />
          <Input v-model.number="form.panel_port" label="面板端口" hint="修改后需重启面板进程生效" type="number" placeholder="8080" />
        </div>
      </div>

      <div class="card">
        <h3 class="card-title">订阅发布</h3>
        <div class="form-grid">
          <Input v-model="form.sub_host" label="订阅主机 (域名/IP)" hint="留空则跟随浏览器访问地址 (反代友好)；可带端口，如 sub.example.com:8443" placeholder="sub.example.com:8443" />
          <Input v-model.number="form.sub_port" label="订阅端口" hint="0 = 跟随订阅地址或请求端口；反代到 443 等场景填 443" type="number" placeholder="0" />
          <Input v-model="form.sub_path" label="订阅路径" hint="默认 sub；修改后旧订阅地址立即失效" placeholder="sub" />
        </div>
        <p class="card-note muted">
          订阅地址泄露时可配合「我的-重置订阅链接」或用户页的「重置订阅」快速换发。
        </p>
      </div>

      <div class="card">
        <h3 class="card-title">管理员账号</h3>
        <div class="form-grid">
          <Input v-model="adminForm.old_password" label="原密码" type="password" placeholder="必填" />
          <Input v-model="adminForm.new_username" label="新用户名" hint="留空则不修改" :placeholder="adminUser" />
          <Input v-model="adminForm.new_password" label="新密码" hint="至少 6 位，留空则不修改" type="password" placeholder="留空则不修改" />
        </div>
        <div class="row foot">
          <span class="muted note">修改后当前登录令牌自动更换，其他会话立即失效。</span>
          <Button variant="primary" :loading="savingAdmin" @click="saveAdmin">修改凭据</Button>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import Button from '@/component/ui/Button.vue'
import Input from '@/component/ui/Input.vue'
import Select from '@/component/ui/Select.vue'
import Spinner from '@/component/ui/Spinner.vue'
import Toggle from '@/component/ui/Toggle.vue'
import { get, post, put } from '@/util/request'
import { toast } from '@/util/toast'
import { auth, login } from '@/util/auth'
import { LOG_LEVELS, type NodeInfo, type Settings } from '@/types'

const loading = ref(true)
const saving = ref(false)
const savingAdmin = ref(false)
const nodeTags = ref<string[]>([])
const adminUser = ref('admin')

const form = reactive({
  host: '',
  sni: '',
  final: 'direct',
  private_action: 'reject',
  auto_detect_interface: true,
  log_level: 'info',
  panel_listen: '',
  panel_port: 8080,
  sub_host: '',
  sub_path: 'sub',
  sub_port: 0,
})

const adminForm = reactive({
  old_password: '',
  new_username: '',
  new_password: '',
})

const finalOptions = computed(() => [
  { label: 'direct 直连', value: 'direct' },
  { label: 'reject 拒绝', value: 'reject' },
  ...nodeTags.value.map((t) => ({ label: `节点: ${t}`, value: t })),
])

async function load() {
  loading.value = true
  try {
    const [s, nd] = await Promise.all([
      get<Settings>('/api/settings'),
      get<Record<string, NodeInfo>>('/api/nodes'),
    ])
    const subHost = s.sub_host || s.host || ''
    Object.assign(form, {
      host: subHost,
      sni: s.sni ?? '',
      final: s.final || 'direct',
      private_action: s.private_action || 'reject',
      auto_detect_interface: !!s.auto_detect_interface,
      log_level: s.log_level || 'info',
      panel_listen: s.panel_listen ?? '',
      panel_port: s.panel_port,
      sub_host: subHost,
      sub_path: s.sub_path || 'sub',
      sub_port: s.sub_port ?? 0,
    })
    adminUser.value = s.admin_user
    adminForm.new_username = s.admin_user
    nodeTags.value = Object.keys(nd).sort()
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    const subHost = form.sub_host.trim()
    await put('/api/settings', {
      ...form,
      host: subHost,
      sub_host: subHost,
      panel_port: Number(form.panel_port),
      sub_port: Number(form.sub_port) || 0,
    })
    toast('设置已保存，等待节点同步', 'success')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    saving.value = false
  }
}

async function saveAdmin() {
  if (!adminForm.old_password) {
    toast('请输入原密码', 'error')
    return
  }
  if (adminForm.new_password && adminForm.new_password.length < 6) {
    toast('新密码至少 6 位', 'error')
    return
  }
  savingAdmin.value = true
  try {
    const body: Record<string, string> = { old_password: adminForm.old_password }
    if (adminForm.new_password) body.new_password = adminForm.new_password
    if (adminForm.new_username.trim()) body.new_username = adminForm.new_username.trim()
    const r = await post<{ ok: boolean; token?: string; name?: string }>('/api/settings/admin', body)
    if (r.token) login(r.token, 'admin', r.name || auth.name) // 凭据变更后旧令牌失效, 换新令牌
    toast('管理员凭据已更新', 'success')
    adminForm.old_password = ''
    adminForm.new_password = ''
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    savingAdmin.value = false
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

.card-note {
  margin: 12px 0 0;
  font-size: 12.5px;
}

.foot {
  margin-top: 16px;
  justify-content: flex-end;
  flex-wrap: wrap;
}

.foot .note {
  font-size: 12.5px;
  margin-right: auto;
}
</style>
