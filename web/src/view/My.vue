<template>
  <div>
    <Spinner v-if="loading" />

    <template v-else-if="me">
      <div class="card hero">
        <h2>你好，{{ me.name }}</h2>
        <p class="muted">这是你的 AnyTLS 代理接入信息。</p>
        <div v-if="!me.enable" class="tip-bar" style="margin: 12px 0 0">
          账号已被禁用，如有疑问请联系管理员。
        </div>
      </div>

      <div class="card">
        <h3 class="card-title">我的节点</h3>

        <h4 class="sec">AnyTLS 链接</h4>
        <template v-if="links.length">
          <div v-for="(link, i) in links" :key="i" class="link-item">
            <p class="link-name">{{ linkName(link, i) }}</p>
            <CodeBox :text="link" />
            <div class="qr-row">
              <QrCode v-if="i === 0" :text="link" />
              <CopyButton :text="link" :label="`复制链接 ${i + 1}`" />
            </div>
          </div>
        </template>
        <p v-else class="muted">{{ me.enable ? '暂无可用服务器节点，请联系管理员。' : '账号已禁用，暂无可用链接。' }}</p>

        <h4 class="sec">订阅地址</h4>
        <template v-if="subEntries.length">
          <div v-for="e in subEntries" :key="e.key" class="sub-line">
            <span class="sub-label">{{ e.label }}</span>
            <CodeBox :text="e.url" class="sub-box" />
            <CopyButton :text="e.url" label="复制" />
          </div>
          <div class="row" style="margin-top: 12px">
            <Button variant="danger" small :loading="resetting" @click="resetSub">重置订阅链接</Button>
          </div>
          <p class="muted hint">按客户端类型选择订阅地址；无法识别时会按 UA 自动判断，直接填 v2rayN 那条通常也能用。订阅链接泄露时可一键重置，旧链接立即失效。</p>
        </template>
        <p v-else class="muted">暂无订阅地址，请使用上方 AnyTLS 链接。</p>

        <h4 class="sec">账号信息</h4>
        <div class="kv"><span class="k">已用流量</span><span class="v mono">{{ fmtBytes((me.traffic?.up || 0) + (me.traffic?.down || 0)) }}</span></div>
        <div class="kv"><span class="k">服务器端口</span><span class="v mono">{{ me.server_port }}</span></div>
        <div class="kv"><span class="k">SNI</span><span class="v mono">{{ me.sni || '-' }}</span></div>
        <div class="kv"><span class="k">当前出口</span><span class="v"><Badge :color="me.exit === 'reject' ? 'red' : me.exit === 'direct' ? 'dim' : 'cyan'">{{ me.exit }}</Badge></span></div>
        <div class="kv"><span class="k">专属规则数</span><span class="v">{{ me.my_rules }}</span></div>
        <div class="kv"><span class="k">账号状态</span><span class="v"><Badge :color="me.enable ? 'green' : 'red'">{{ me.enable ? '正常' : '已禁用' }}</Badge></span></div>
      </div>

      <div class="card">
        <h3 class="card-title">修改面板密码</h3>
        <div class="form-grid">
          <Input v-model="oldPwd" label="原密码" type="password" placeholder="当前面板密码" />
          <Input v-model="newPwd" label="新密码" hint="至少 6 位" type="password" placeholder="新密码" />
        </div>
        <div class="row" style="margin-top: 16px; justify-content: flex-end">
          <Button variant="primary" :loading="saving" @click="changePwd">修改密码</Button>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Input from '@/component/ui/Input.vue'
import Spinner from '@/component/ui/Spinner.vue'
import CodeBox from '@/component/widget/CodeBox.vue'
import CopyButton from '@/component/widget/CopyButton.vue'
import QrCode from '@/component/widget/QrCode.vue'
import { get, post } from '@/util/request'
import { toast } from '@/util/toast'
import { confirmDialog } from '@/util/confirm'
import { auth, login } from '@/util/auth'
import { fmtBytes } from '@/util/format'
import type { MeInfo, SubUrls } from '@/types'

const me = ref<MeInfo>()
const loading = ref(true)
const saving = ref(false)
const resetting = ref(false)
const oldPwd = ref('')
const newPwd = ref('')

const links = computed(() => {
  if (!me.value) return [] as string[]
  if (me.value.links?.length) return me.value.links
  return me.value.link ? [me.value.link] : []
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

async function load() {
  loading.value = true
  try {
    me.value = await get<MeInfo>('/api/me')
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
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
  if (!(await confirmDialog('确定重置订阅链接？旧链接将立即失效，客户端需要重新导入。'))) return
  resetting.value = true
  try {
    const r = await post<{ ok: boolean; sub_url: string }>('/api/me/refresh_token', {})
    if (me.value) me.value.sub_url = r.sub_url
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
.hero h2 {
  margin: 0 0 6px;
  font-size: 20px;
}

.hero p {
  margin: 0;
}

.sec {
  margin: 18px 0 10px;
  font-size: 13.5px;
  color: var(--c-text-dim);
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
  margin-top: 8px;
  font-size: 12.5px;
}
</style>
