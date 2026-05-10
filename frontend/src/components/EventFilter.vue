<template>
  <div class="filter-bar">
    <div class="filter-group">
      <label>类别</label>
      <div class="checkbox-group">
        <label class="checkbox" v-for="cat in categories" :key="cat.value">
          <input type="checkbox" v-model="selectedCategories" :value="cat.value" />
          <span class="checkmark" :style="{ borderColor: cat.color }"></span>
          {{ cat.label }}
        </label>
      </div>
    </div>
    <div class="filter-group">
      <label>事件类型</label>
      <select v-model="selectedType" class="select">
        <option value="">全部</option>
        <option v-for="(label, key) in filteredTypeLabels" :key="key" :value="key">{{ label }}</option>
      </select>
    </div>
    <div class="filter-group">
      <label>PID</label>
      <input type="text" v-model="pidFilter" placeholder="输入PID" class="input" />
    </div>
    <div class="filter-group">
      <label>进程名</label>
      <input type="text" v-model="commFilter" placeholder="输入进程名" class="input" />
    </div>
    <div class="filter-group">
      <label>容器</label>
      <input type="text" v-model="containerFilter" placeholder="容器ID/名称" class="input" />
    </div>
    <div class="filter-group">
      <button class="btn-clear" @click="$emit('clear')">清空事件</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { EVENT_TYPE_LABELS } from '../types/event'

const emit = defineEmits<{ (e: 'update:filters', filters: FilterState): void; (e: 'clear'): void }>()

export interface FilterState {
  categories: string[]; eventType: string; pid: string; comm: string; container: string
}

const categories = [
  { value: 'process', label: '进程', color: '#3b82f6' },
  { value: 'network', label: '网络', color: '#10b981' },
  { value: 'file', label: '文件', color: '#f59e0b' },
]

const selectedCategories = ref(['process', 'network', 'file'])
const selectedType = ref('')
const pidFilter = ref('')
const commFilter = ref('')
const containerFilter = ref('')

const filteredTypeLabels = computed(() => {
  const result: Record<string, string> = {}
  for (const [key, label] of Object.entries(EVENT_TYPE_LABELS)) {
    const cat = key.split('_')[0]
    if (selectedCategories.value.includes(cat) || (cat === 'privilege' && selectedCategories.value.includes('process')))
      result[key] = label
  }
  return result
})

watch([selectedCategories, selectedType, pidFilter, commFilter, containerFilter], () => {
  emit('update:filters', {
    categories: selectedCategories.value, eventType: selectedType.value,
    pid: pidFilter.value, comm: commFilter.value, container: containerFilter.value,
  })
}, { immediate: true })
</script>

<style scoped>
.filter-bar { display: flex; gap: 16px; padding: 12px 24px; background: #16162a; border-bottom: 1px solid #2a2a4a; flex-wrap: wrap; align-items: flex-end; }
.filter-group { display: flex; flex-direction: column; gap: 4px; }
.filter-group > label { font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
.checkbox-group { display: flex; gap: 12px; }
.checkbox { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 13px; color: #e2e8f0; }
.checkbox input { display: none; }
.checkmark { width: 16px; height: 16px; border: 2px solid; border-radius: 3px; position: relative; transition: all 0.2s; }
.checkbox input:checked + .checkmark { background: currentColor; }
.checkbox input:checked + .checkmark::after { content: '✓'; position: absolute; top: -2px; left: 1px; font-size: 12px; color: #0f0f23; font-weight: bold; }
.select, .input { padding: 6px 10px; background: #0f0f23; border: 1px solid #2a2a4a; border-radius: 4px; color: #e2e8f0; font-size: 13px; min-width: 120px; outline: none; transition: border-color 0.2s; }
.select:focus, .input:focus { border-color: #3b82f6; }
.btn-clear { padding: 6px 14px; background: #1e293b; border: 1px solid #334155; border-radius: 4px; color: #94a3b8; cursor: pointer; font-size: 13px; transition: all 0.2s; }
.btn-clear:hover { background: #334155; color: #e2e8f0; }
</style>
