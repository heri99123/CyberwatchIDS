// CyberWatch IDS — WebSocket client with auto-reconnect (multi-tenant)
import type { WSMessage } from './types'
import { getToken } from './client'

type WSHandler = (msg: WSMessage) => void

export class WebSocketClient {
  private ws: WebSocket | null = null
  private url: string
  private handlers: Set<WSHandler> = new Set()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectDelay = 3000
  private closed = false

  constructor(url?: string) {
    if (url) {
      this.url = url
    } else {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
      this.url = `${proto}//${location.host}/ws`
    }
  }

  connect() {
    if (this.closed) return
    try {
      // Pass token as query param for multi-tenant org scoping
      const token = getToken()
      const wsUrl = token ? `${this.url}?token=${encodeURIComponent(token)}` : this.url
      this.ws = new WebSocket(wsUrl)
    } catch {
      this.scheduleReconnect()
      return
    }

    this.ws.onopen = () => {
      // Subscribe to all channels
      this.ws?.send(JSON.stringify({ type: 'subscribe', channels: ['events', 'alerts', 'stats'] }))
      // Send auth token for org scoping
      const token = getToken()
      if (token) {
        this.ws?.send(JSON.stringify({ type: 'auth', token }))
      }
    }

    this.ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data) as WSMessage
        this.handlers.forEach(h => h(msg))
      } catch {
        // ignore non-JSON messages
      }
    }

    this.ws.onclose = () => {
      if (!this.closed) this.scheduleReconnect()
    }

    this.ws.onerror = () => {
      this.ws?.close()
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.reconnectTimer = setTimeout(() => this.connect(), this.reconnectDelay)
  }

  on(handler: WSHandler): () => void {
    this.handlers.add(handler)
    return () => this.handlers.delete(handler)
  }

  close() {
    this.closed = true
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.ws?.close()
    this.ws = null
  }
}
