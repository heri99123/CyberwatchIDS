// CyberWatch IDS — API client (v3.0 — Multi-tenant with auth)
import type {
  SecurityEvent, CVEEntry, IDSRule, Alert,
  IPReputation, Stats, SimulatorStatus
} from './types'

const API_BASE = '/api'

// --- Auth token management ---
const TOKEN_KEY = 'cw_token'
const USER_KEY = 'cw_user'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export function getStoredUser(): { id: string; email: string; name: string; role: string; orgId: string; orgName: string } | null {
  try {
    const raw = localStorage.getItem(USER_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

export function setStoredUser(user: any) {
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

// --- Fetch with auth header ---
async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    ...(options?.headers as Record<string, string> || {})
  }
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }
  if (options?.body && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }
  const res = await fetch(url, { ...options, headers })
  if (res.status === 401) {
    clearToken()
    window.location.hash = '#/login'
    throw new Error('Session expired. Please login again.')
  }
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`API ${res.status}: ${body}`)
  }
  return res.json() as Promise<T>
}

// --- Auth API ---
export const authApi = {
  register(orgName: string, name: string, email: string, password: string) {
    return fetchJSON<{ token: string; user: any; organization: any }>(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orgName, name, email, password })
    })
  },
  login(email: string, password: string) {
    return fetchJSON<{ token: string; user: any; organization: any }>(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
  },
  verify() {
    return fetchJSON<{ user: any; organization: any }>(`${API_BASE}/auth/verify`)
  },
  me() {
    return fetchJSON<{ user: any }>(`${API_BASE}/auth/me`)
  }
}

// --- Admin API ---
export const adminApi = {
  getOrg() {
    return fetchJSON<any>(`${API_BASE}/admin/org`)
  },
  updateOrg(data: { name?: string; settings?: any }) {
    return fetchJSON<any>(`${API_BASE}/admin/org`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
  },
  getUsers() {
    return fetchJSON<any[]>(`${API_BASE}/admin/users`)
  },
  createUser(data: { email: string; name: string; password: string; role?: string }) {
    return fetchJSON<any>(`${API_BASE}/admin/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
  },
  updateUserRole(id: string, role: string) {
    return fetchJSON<any>(`${API_BASE}/admin/users/${id}/role`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role })
    })
  },
  updateUserStatus(id: string, status: string) {
    return fetchJSON<any>(`${API_BASE}/admin/users/${id}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    })
  },
  deleteUser(id: string) {
    return fetchJSON<any>(`${API_BASE}/admin/users/${id}`, { method: 'DELETE' })
  },
  getApiKeys() {
    return fetchJSON<any[]>(`${API_BASE}/admin/api-keys`)
  },
  createApiKey(name: string, permissions = 'read') {
    return fetchJSON<any>(`${API_BASE}/admin/api-keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, permissions })
    })
  },
  revokeApiKey(id: string) {
    return fetchJSON<any>(`${API_BASE}/admin/api-keys/${id}`, { method: 'DELETE' })
  },
  getAuditLogs(limit = 100) {
    return fetchJSON<any[]>(`${API_BASE}/admin/audit-logs?limit=${limit}`)
  },
  exportData(type: string) {
    return fetchJSON<any>(`${API_BASE}/admin/export/${type}`)
  }
}

// --- Incidents API ---
export const incidentApi = {
  list() {
    return fetchJSON<any[]>(`${API_BASE}/incidents`)
  },
  create(data: { title: string; description?: string; severity?: string; eventIds?: number[] }) {
    return fetchJSON<any>(`${API_BASE}/incidents`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
  },
  update(id: string, data: { status?: string; severity?: string; assignedTo?: string; description?: string }) {
    return fetchJSON<any>(`${API_BASE}/incidents/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
  }
}

// --- Notifications API ---
export const notifApi = {
  list() {
    return fetchJSON<any[]>(`${API_BASE}/notifications`)
  },
  markRead(id: number) {
    return fetchJSON<any>(`${API_BASE}/notifications/${id}/read`, { method: 'PUT' })
  }
}

export const api = {
  // Events
  getEvents(limit = 50): Promise<SecurityEvent[]> {
    return fetchJSON(`${API_BASE}/events?limit=${limit}`)
  },
  searchEvents(params: { severity?: string; attack_type?: string; source_ip?: string }): Promise<SecurityEvent[]> {
    const qs = new URLSearchParams()
    if (params.severity) qs.set('severity', params.severity)
    if (params.attack_type) qs.set('attack_type', params.attack_type)
    if (params.source_ip) qs.set('source_ip', params.source_ip)
    return fetchJSON(`${API_BASE}/events/search?${qs}`)
  },

  // CVE
  getCVEs(query = '', severity = 'ALL'): Promise<CVEEntry[]> {
    const qs = new URLSearchParams()
    if (query) qs.set('q', query)
    if (severity !== 'ALL') qs.set('severity', severity)
    return fetchJSON(`${API_BASE}/cve?${qs}`)
  },
  getCVEById(id: string): Promise<CVEEntry> {
    return fetchJSON(`${API_BASE}/cve/${id}`)
  },

  // Rules
  getRules(): Promise<IDSRule[]> {
    return fetchJSON(`${API_BASE}/rules`)
  },
  toggleRule(id: string): Promise<{ rule_id: string; enabled: number }> {
    return fetchJSON(`${API_BASE}/rules/${id}/toggle`, { method: 'PUT' })
  },

  // IP Reputation
  getIPReputation(): Promise<IPReputation[]> {
    return fetchJSON(`${API_BASE}/ip-reputation`)
  },
  blockIP(ip: string): Promise<{ ip: string; blocked: boolean }> {
    return fetchJSON(`${API_BASE}/ip-reputation/${encodeURIComponent(ip)}/block`, { method: 'PUT' })
  },
  unblockIP(ip: string): Promise<{ ip: string; blocked: boolean }> {
    return fetchJSON(`${API_BASE}/ip-reputation/${encodeURIComponent(ip)}/unblock`, { method: 'PUT' })
  },

  // Alerts
  getAlerts(unacknowledgedOnly = false): Promise<Alert[]> {
    return fetchJSON(`${API_BASE}/alerts${unacknowledgedOnly ? '?unacknowledged=true' : ''}`)
  },
  acknowledgeAlert(id: number, user = 'admin'): Promise<{ acknowledged: boolean }> {
    return fetchJSON(`${API_BASE}/alerts/${id}/acknowledge`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user })
    })
  },

  // Stats
  getStats(): Promise<Stats> {
    return fetchJSON(`${API_BASE}/stats`)
  },

  // Dashboard
  getDashboard(): Promise<any> {
    return fetchJSON(`${API_BASE}/dashboard`)
  },

  // Reset
  resetData(): Promise<{ status: string; purged: Record<string, number> }> {
    return fetchJSON(`${API_BASE}/reset`, { method: 'POST' })
  },

  // Simulator
  startSimulator(interval = 3000): Promise<{ status: string; interval: number }> {
    return fetchJSON(`${API_BASE}/simulate/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interval })
    })
  },
  stopSimulator(): Promise<{ status: string }> {
    return fetchJSON(`${API_BASE}/simulate/stop`, { method: 'POST' })
  },
  getSimulatorStatus(): Promise<SimulatorStatus> {
    return fetchJSON(`${API_BASE}/simulate/status`)
  },
  injectAttack(attack_type: string): Promise<{ fired: boolean; event: SecurityEvent }> {
    return fetchJSON(`${API_BASE}/simulate/attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type })
    })
  }
}
