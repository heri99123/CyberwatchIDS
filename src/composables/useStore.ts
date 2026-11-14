// Shared reactive store for CyberWatch IDS
import { reactive, ref } from 'vue'
import { api } from '@/api/client'
import { WebSocketClient } from '@/api/websocket'
import type { Stats, SecurityEvent, Alert } from '@/api/types'

const state = reactive({
  stats: null as Stats | null,
  liveFeed: [] as SecurityEvent[],
  alerts: [] as Alert[],
  wsConnected: false,
  lastUpdated: '' as string
})

const ws = ref<WebSocketClient | null>(null)

export function useStore() {
  async function loadStats() {
    try {
      state.stats = await api.getStats()
      state.lastUpdated = new Date().toLocaleTimeString('id-ID')
    } catch (e) {
      console.error('[store] Failed to load stats:', e)
    }
  }

  async function loadInitialFeed() {
    try {
      const events = await api.getEvents(20)
      state.liveFeed = events.reverse()
    } catch (e) {
      console.error('[store] Failed to load feed:', e)
    }
  }

  function initWebSocket() {
    if (ws.value) return
    ws.value = new WebSocketClient()
    ws.value.connect()

    ws.value.on((msg) => {
      if (msg.type === 'stats') {
        state.stats = msg.data as Stats
        state.lastUpdated = new Date().toLocaleTimeString('id-ID')
        state.wsConnected = true
      } else if (msg.type === 'events') {
        const evt = msg.data as SecurityEvent
        state.liveFeed.unshift(evt)
        if (state.liveFeed.length > 50) state.liveFeed.pop()
      } else if (msg.type === 'alerts') {
        state.alerts.unshift(msg.data as Alert)
        if (state.alerts.length > 100) state.alerts.pop()
      }
    })
  }

  function destroy() {
    ws.value?.close()
    ws.value = null
  }

  return {
    state,
    loadStats,
    loadInitialFeed,
    initWebSocket,
    destroy
  }
}
