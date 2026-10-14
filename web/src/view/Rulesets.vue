<template>
  <div>
    <div class="page-head">
      <h2>规则集</h2>
      <span class="muted">共 {{ total }} 个</span>
      <div class="spacer"></div>
      <input v-model="q" class="search" placeholder="搜索关键字，空格分隔" @input="debouncedSearch" />
      <Select v-model="source" :options="sourceOptions" style="width: 200px" />
    </div>

    <div class="card">
      <Spinner v-if="loading" />
      <Empty v-else-if="!list.length" text="无匹配的规则集" />
      <div v-else class="table-wrap">
        <table class="tbl">
          <thead>
            <tr>
              <th>标签</th>
              <th>来源</th>
              <th>本地路径</th>
              <th>远程 URL</th>
              <th style="width: 90px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in list" :key="r.tag">
              <td class="mono">{{ r.tag }}</td>
              <td><Badge color="purple">{{ r.source }}</Badge></td>
              <td>
                <div class="row" style="gap: 6px">
                  <span class="mono muted ellipsis">{{ r.path }}</span>
                  <CopyButton :text="r.path" small />
                </div>
              </td>
              <td>
                <div class="row" style="gap: 6px">
                  <a :href="r.url" target="_blank" rel="noopener" class="mono ellipsis">{{ r.url }}</a>
                  <CopyButton :text="r.url" small />
                </div>
              </td>
              <td>
                <Button small variant="primary" @click="useForRoute(r.tag)">用于分流</Button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import Badge from '@/component/ui/Badge.vue'
import Button from '@/component/ui/Button.vue'
import Empty from '@/component/ui/Empty.vue'
import Select from '@/component/ui/Select.vue'
import Spinner from '@/component/ui/Spinner.vue'
import CopyButton from '@/component/widget/CopyButton.vue'
import { get } from '@/util/request'
import { toast } from '@/util/toast'
import type { RulesetItem, RulesetSource } from '@/types'

const router = useRouter()
const q = ref('')
const source = ref('')
const sources = ref<RulesetSource[]>([])
const list = ref<RulesetItem[]>([])
const total = ref(0)
const loading = ref(true)

const sourceOptions = computed(() => [
  { label: '全部来源', value: '' },
  ...sources.value.map((s) => ({ label: `${s.key} - ${s.desc}`, value: s.key })),
])

let timer: ReturnType<typeof setTimeout> | undefined

function debouncedSearch() {
  clearTimeout(timer)
  timer = setTimeout(search, 300)
}

async function search() {
  loading.value = true
  try {
    const params = new URLSearchParams()
    if (q.value.trim()) params.set('q', q.value.trim())
    if (source.value) params.set('source', source.value)
    const r = await get<{ total: number; results: RulesetItem[] }>(`/api/rulesets?${params}`)
    total.value = r.total
    list.value = r.results
  } catch (e) {
    toast((e as Error).message, 'error')
  } finally {
    loading.value = false
  }
}

function useForRoute(tag: string) {
  router.push({ path: '/routes', query: { set: tag } })
}

watch(source, search)

onMounted(async () => {
  try {
    sources.value = await get<RulesetSource[]>('/api/rulesets/sources')
  } catch (e) {
    toast((e as Error).message, 'error')
  }
  search()
})
</script>

<style scoped>
.search {
  width: 240px;
  padding: 7px 11px;
  border-radius: 6px;
  border: 1px solid var(--c-border);
  background: var(--c-card);
  color: var(--c-text);
  font-size: 13.5px;
  font-family: var(--font);
  outline: none;
}

.search:focus {
  border-color: var(--c-primary);
}

.ellipsis {
  display: inline-block;
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  vertical-align: middle;
}
</style>
