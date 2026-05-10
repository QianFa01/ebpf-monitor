<template>
  <div class="app">
    <header class="header">
      <div class="logo">
        <span class="logo-icon">🛡️</span>
        <h1>eBPF Security Monitor</h1>
      </div>
      <div class="header-info">
        <span class="time">{{ currentTime }}</span>
      </div>
    </header>
    <StatsBar :stats="stats" :connected="connected" />
    <EventFilter @update:filters="filters = $event" @clear="events.length = 0" />
    <EventTable :events="events" :filters="filters" />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import StatsBar from './components/StatsBar.vue'
import EventFilter from './components/EventFilter.vue'
import EventTable from './components/EventTable.vue'
import type { FilterState } from './components/EventFilter.vue'
import { useWebSocket } from './composables/useWebSocket'

const { events, stats, connected } = useWebSocket()
const filters = ref<FilterState>({ categories: ['process', 'network', 'file'], eventType: '', pid: '', comm: '', container: '' })
const currentTime = ref('')
let timeTimer: number
onMounted(() => {
  const updateTime = () => { currentTime.value = new Date().toLocaleTimeString('zh-CN', { hour12: false }) }
  updateTime()
  timeTimer = window.setInterval(updateTime, 1000)
})
onUnmounted(() => { clearInterval(timeTimer) })
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a1a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; overflow: hidden; }
#app { height: 100vh; display: flex; flex-direction: column; }
.app { display: flex; flex-direction: column; height: 100vh; }
.header { display: flex; justify-content: space-between; align-items: center; padding: 12px 24px; background: #0f0f23; border-bottom: 2px solid #1e3a5f; flex-shrink: 0; }
.logo { display: flex; align-items: center; gap: 12px; }
.logo-icon { font-size: 24px; }
.logo h1 { font-size: 18px; font-weight: 700; color: #e2e8f0; letter-spacing: 0.5px; }
.header-info { display: flex; align-items: center; gap: 16px; }
.time { font-family: 'JetBrains Mono', monospace; font-size: 14px; color: #64748b; }
</style>
