import { ref, onUnmounted } from 'vue'
import type { SecurityEvent, EventStats } from '../types/event'

export function useWebSocket() {
  const events = ref<SecurityEvent[]>([])
  const stats = ref<EventStats>({
    total_events: 0, events_per_sec: 0, by_category: {}, by_type: {},
    connected_clients: 0, last_event_time: '',
  })
  const connected = ref(false)
  const maxEvents = 10000

  let ws: WebSocket | null = null
  let reconnectTimer: number | null = null
  let statsTimer: number | null = null
  let reconnectDelay = 1000

  function getWsUrl(): string {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${protocol}//${window.location.host}/ws`
  }

  function connect() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return
    ws = new WebSocket(getWsUrl())
    ws.onopen = () => { connected.value = true; reconnectDelay = 1000 }
    ws.onmessage = (event) => {
      try {
        for (const msg of event.data.split('\n')) {
          if (!msg.trim()) continue
          events.value.push(JSON.parse(msg))
        }
        if (events.value.length > maxEvents) events.value = events.value.slice(-maxEvents)
      } catch (e) { console.error('Failed to parse WebSocket message:', e) }
    }
    ws.onclose = () => { connected.value = false; scheduleReconnect() }
    ws.onerror = () => { ws?.close() }
  }

  function scheduleReconnect() {
    if (reconnectTimer) return
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null
      reconnectDelay = Math.min(reconnectDelay * 2, 30000)
      connect()
    }, reconnectDelay)
  }

  function fetchStats() {
    fetch('/api/stats').then(res => res.json()).then(data => { stats.value = data }).catch(() => {})
  }

  function startStatsPolling() {
    fetchStats()
    statsTimer = window.setInterval(fetchStats, 3000)
  }

  function disconnect() {
    if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null }
    if (statsTimer) { clearInterval(statsTimer); statsTimer = null }
    ws?.close(); ws = null
  }

  connect()
  startStatsPolling()
  onUnmounted(() => { disconnect() })

  return { events, stats, connected, disconnect }
}
