<template>
  <div class="stats-bar">
    <div class="stat-item">
      <span class="stat-value">{{ formatNumber(stats.total_events) }}</span>
      <span class="stat-label">总事件数</span>
    </div>
    <div class="stat-item">
      <span class="stat-value">{{ stats.events_per_sec.toFixed(1) }}</span>
      <span class="stat-label">事件/秒</span>
    </div>
    <div class="stat-item">
      <span class="stat-value" style="color: #3b82f6">{{ stats.by_category?.process || 0 }}</span>
      <span class="stat-label">进程事件</span>
    </div>
    <div class="stat-item">
      <span class="stat-value" style="color: #10b981">{{ stats.by_category?.network || 0 }}</span>
      <span class="stat-label">网络事件</span>
    </div>
    <div class="stat-item">
      <span class="stat-value" style="color: #f59e0b">{{ stats.by_category?.file || 0 }}</span>
      <span class="stat-label">文件事件</span>
    </div>
    <div class="stat-item">
      <span class="stat-value" style="color: #ef4444">{{ stats.by_type?.privilege_escalation || 0 }}</span>
      <span class="stat-label">权限提升</span>
    </div>
    <div class="stat-item connection" :class="{ online: connected }">
      <span class="stat-dot"></span>
      <span class="stat-label">{{ connected ? '已连接' : '未连接' }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import type { EventStats } from '../types/event'
defineProps<{ stats: EventStats; connected: boolean }>()
function formatNumber(n: number): string {
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M'
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K'
  return n.toString()
}
</script>

<style scoped>
.stats-bar { display: flex; gap: 24px; padding: 16px 24px; background: #1a1a2e; border-bottom: 1px solid #2a2a4a; flex-wrap: wrap; }
.stat-item { display: flex; flex-direction: column; align-items: center; min-width: 80px; }
.stat-value { font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', 'Fira Code', monospace; color: #e2e8f0; }
.stat-label { font-size: 11px; color: #94a3b8; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-item.connection { margin-left: auto; display: flex; flex-direction: row; align-items: center; gap: 8px; }
.stat-dot { width: 10px; height: 10px; border-radius: 50%; background: #ef4444; transition: background 0.3s; }
.stat-item.online .stat-dot { background: #10b981; box-shadow: 0 0 8px #10b981; }
</style>
