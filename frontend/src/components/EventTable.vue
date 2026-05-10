<template>
  <div class="event-table-container">
    <div class="table-header">
      <span class="col-time">时间</span>
      <span class="col-category">类别</span>
      <span class="col-type">事件类型</span>
      <span class="col-pid">PID</span>
      <span class="col-comm">进程</span>
      <span class="col-detail">详情</span>
      <span class="col-container">容器</span>
    </div>
    <div class="table-body" ref="tableBody">
      <div v-for="(event, index) in filteredEvents" :key="index" class="table-row"
        :class="{ 'priv-esc': event.event_type === 'privilege_escalation', 'new-event': isNewEvent(index) }"
        :style="{ borderLeftColor: getEventColor(event.event_type) }">
        <span class="col-time">{{ formatTime(event.timestamp) }}</span>
        <span class="col-category">
          <span class="badge" :style="{ background: getCategoryColor(event.category) }">{{ getCategoryLabel(event.category) }}</span>
        </span>
        <span class="col-type">
          <span class="type-tag" :style="{ color: getEventColor(event.event_type) }">{{ getEventTypeLabel(event.event_type) }}</span>
        </span>
        <span class="col-pid">{{ event.pid }}</span>
        <span class="col-comm">{{ event.comm }}</span>
        <span class="col-detail">{{ getEventDetail(event) }}</span>
        <span class="col-container">
          <span v-if="event.container_id" class="container-badge">{{ event.container_name || event.container_id.substring(0, 8) }}</span>
          <span v-else class="host-badge">HOST</span>
        </span>
      </div>
      <div v-if="filteredEvents.length === 0" class="empty-state">等待事件...</div>
    </div>
    <div class="table-footer">
      <span>显示 {{ filteredEvents.length }} / {{ totalEvents }} 条事件</span>
      <label class="auto-scroll"><input type="checkbox" v-model="autoScroll" /> 自动滚动</label>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, nextTick } from 'vue'
import type { SecurityEvent } from '../types/event'
import { EVENT_TYPE_LABELS, CATEGORY_COLORS, EVENT_TYPE_COLORS } from '../types/event'

const props = defineProps<{
  events: SecurityEvent[]
  filters: { categories: string[]; eventType: string; pid: string; comm: string; container: string }
}>()

const tableBody = ref<HTMLElement | null>(null)
const autoScroll = ref(true)
const lastEventCount = ref(0)

const filteredEvents = computed(() => {
  let result = [...props.events].reverse()
  const f = props.filters
  if (f.categories.length > 0 && f.categories.length < 3) result = result.filter(e => f.categories.includes(e.category))
  if (f.eventType) result = result.filter(e => e.event_type === f.eventType)
  if (f.pid) { const pid = parseInt(f.pid); if (!isNaN(pid)) result = result.filter(e => e.pid === pid) }
  if (f.comm) { const q = f.comm.toLowerCase(); result = result.filter(e => e.comm.toLowerCase().includes(q)) }
  if (f.container) { const q = f.container.toLowerCase(); result = result.filter(e => (e.container_id && e.container_id.toLowerCase().includes(q)) || (e.container_name && e.container_name.toLowerCase().includes(q))) }
  return result.slice(0, 5000)
})

const totalEvents = computed(() => props.events.length)
function isNewEvent(index: number): boolean { return index < (filteredEvents.value.length - lastEventCount.value) }

watch(() => filteredEvents.value.length, (newLen) => {
  if (autoScroll.value) nextTick(() => { if (tableBody.value) tableBody.value.scrollTop = 0 })
  setTimeout(() => { lastEventCount.value = newLen }, 500)
})

function formatTime(ns: number): string {
  const date = new Date(ns / 1000000)
  const h = date.getHours().toString().padStart(2, '0')
  const m = date.getMinutes().toString().padStart(2, '0')
  const s = date.getSeconds().toString().padStart(2, '0')
  const ms = date.getMilliseconds().toString().padStart(3, '0')
  return `${h}:${m}:${s}.${ms}`
}
function getCategoryLabel(cat: string): string { return { process: '进程', network: '网络', file: '文件' }[cat] || cat }
function getCategoryColor(cat: string): string { return CATEGORY_COLORS[cat] || '#6b7280' }
function getEventTypeLabel(type: string): string { return EVENT_TYPE_LABELS[type] || type }
function getEventColor(type: string): string { return EVENT_TYPE_COLORS[type] || '#6b7280' }
function getEventDetail(e: SecurityEvent): string {
  switch (e.category) {
    case 'process':
      if (e.event_type === 'privilege_escalation') return `${e.filename || ''} (uid: ${e.old_uid} → ${e.uid})`
      if (e.event_type === 'process_exit') return `${e.filename || e.comm} exit_code=${e.exit_code}`
      return e.filename || e.comm
    case 'network': {
      const proto = e.protocol === 6 ? 'TCP' : e.protocol === 17 ? 'UDP' : `P${e.protocol}`
      return `${proto} ${e.src_addr}:${e.src_port} → ${e.dst_addr}:${e.dst_port}`
    }
    case 'file':
      if (e.event_type === 'file_rename') return `${e.old_filename} → ${e.filename}`
      if (e.event_type === 'file_chmod') return `${e.filename} mode=${e.mode?.toString(8)}`
      if (e.event_type === 'file_modify') return `${e.filename} (${e.write_bytes || 0} bytes)`
      return e.filename || ''
    default: return ''
  }
}
</script>

<style scoped>
.event-table-container { flex: 1; display: flex; flex-direction: column; overflow: hidden; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 12px; }
.table-header { display: flex; padding: 8px 16px; background: #0f0f23; border-bottom: 1px solid #2a2a4a; font-weight: 600; color: #94a3b8; text-transform: uppercase; font-size: 10px; letter-spacing: 0.5px; flex-shrink: 0; }
.table-body { flex: 1; overflow-y: auto; background: #0a0a1a; }
.table-row { display: flex; padding: 6px 16px; border-bottom: 1px solid #1a1a2e; border-left: 3px solid transparent; transition: background 0.15s; align-items: center; }
.table-row:hover { background: #1a1a3e; }
.table-row.priv-esc { background: rgba(239, 68, 68, 0.08); border-left-color: #ef4444 !important; animation: pulse-red 2s infinite; }
.table-row.new-event { animation: flash-in 0.5s ease-out; }
@keyframes flash-in { 0% { background: rgba(59, 130, 246, 0.2); } 100% { background: transparent; } }
@keyframes pulse-red { 0%, 100% { background: rgba(239, 68, 68, 0.05); } 50% { background: rgba(239, 68, 68, 0.12); } }
.col-time { width: 100px; color: #64748b; flex-shrink: 0; }
.col-category { width: 60px; flex-shrink: 0; }
.col-type { width: 110px; flex-shrink: 0; }
.col-pid { width: 60px; color: #94a3b8; flex-shrink: 0; }
.col-comm { width: 100px; color: #e2e8f0; flex-shrink: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.col-detail { flex: 1; color: #cbd5e1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.col-container { width: 100px; flex-shrink: 0; text-align: right; }
.badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; color: #fff; }
.type-tag { font-weight: 500; }
.container-badge { display: inline-block; padding: 1px 6px; background: #1e293b; border: 1px solid #334155; border-radius: 3px; font-size: 10px; color: #94a3b8; }
.host-badge { display: inline-block; padding: 1px 6px; background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 3px; font-size: 10px; color: #475569; }
.empty-state { padding: 60px; text-align: center; color: #475569; font-size: 16px; }
.table-footer { display: flex; justify-content: space-between; align-items: center; padding: 8px 16px; background: #0f0f23; border-top: 1px solid #2a2a4a; font-size: 11px; color: #64748b; flex-shrink: 0; }
.auto-scroll { display: flex; align-items: center; gap: 6px; cursor: pointer; }
</style>
