<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { adminApi, incidentApi, clearToken } from '@/api/client'

const emit = defineEmits<{ (e: 'logout'): void }>()

type AdminTab = 'users' | 'org' | 'apikeys' | 'incidents' | 'audit' | 'export'
const activeAdminTab = ref<AdminTab>('users')

const users = ref<any[]>([])
const orgInfo = ref<any>(null)
const apiKeys = ref<any[]>([])
const incidents = ref<any[]>([])
const auditLogs = ref<any[]>([])

// New user form
const newUser = ref({ email: '', name: '', password: '', role: 'viewer' })
const createUserLoading = ref(false)
const createUserMsg = ref('')

// New API key form
const newKeyName = ref('')
const newKeyPerms = ref('read')
const createdKey = ref('')
const createKeyLoading = ref(false)

// New incident form
const newIncident = ref({ title: '', description: '', severity: 'medium' })
const createIncidentLoading = ref(false)

const tabs = [
  { id: 'users' as AdminTab, label: 'Users', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z' },
  { id: 'org' as AdminTab, label: 'Organization', icon: 'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5' },
  { id: 'apikeys' as AdminTab, label: 'API Keys', icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-4a1 1 0 011-1h2.743L8.257 9.757A6 6 0 0121 9z' },
  { id: 'incidents' as AdminTab, label: 'Incidents', icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z' },
  { id: 'audit' as AdminTab, label: 'Audit Logs', icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z' },
  { id: 'export' as AdminTab, label: 'Export', icon: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4' }
]

onMounted(() => {
  loadAll()
})

async function loadAll() {
  try {
    const [u, o, k, i, l] = await Promise.all([
      adminApi.getUsers(),
      adminApi.getOrg(),
      adminApi.getApiKeys(),
      incidentApi.list(),
      adminApi.getAuditLogs(50)
    ])
    users.value = u
    orgInfo.value = o
    apiKeys.value = k
    incidents.value = i
    auditLogs.value = l
  } catch (e) {
    console.error('Failed to load admin data:', e)
  }
}

async function handleCreateUser() {
  createUserLoading.value = true
  createUserMsg.value = ''
  try {
    await adminApi.createUser(newUser.value)
    newUser.value = { email: '', name: '', password: '', role: 'viewer' }
    users.value = await adminApi.getUsers()
    createUserMsg.value = 'User berhasil dibuat'
  } catch (e: any) {
    createUserMsg.value = e.message || 'Gagal membuat user'
  } finally {
    createUserLoading.value = false
  }
}

async function handleRoleChange(id: string, role: string) {
  try {
    await adminApi.updateUserRole(id, role)
    users.value = await adminApi.getUsers()
  } catch (e) {
    console.error('Failed to update role:', e)
  }
}

async function handleToggleStatus(id: string, currentStatus: string) {
  const newStatus = currentStatus === 'active' ? 'disabled' : 'active'
  try {
    await adminApi.updateUserStatus(id, newStatus)
    users.value = await adminApi.getUsers()
  } catch (e) {
    console.error('Failed to update status:', e)
  }
}

async function handleDeleteUser(id: string, name: string) {
  if (!confirm(`Hapus user "${name}"? Tindakan ini tidak dapat dibatalkan.`)) return
  try {
    await adminApi.deleteUser(id)
    users.value = await adminApi.getUsers()
  } catch (e) {
    console.error('Failed to delete user:', e)
  }
}

async function handleCreateKey() {
  createKeyLoading.value = true
  createdKey.value = ''
  try {
    const result = await adminApi.createApiKey(newKeyName.value, newKeyPerms.value)
    createdKey.value = result.key
    newKeyName.value = ''
    apiKeys.value = await adminApi.getApiKeys()
  } catch (e: any) {
    console.error('Failed to create API key:', e)
  } finally {
    createKeyLoading.value = false
  }
}

async function handleRevokeKey(id: string) {
  if (!confirm('Revoke API key ini?')) return
  try {
    await adminApi.revokeApiKey(id)
    apiKeys.value = await adminApi.getApiKeys()
  } catch (e) {
    console.error('Failed to revoke key:', e)
  }
}

async function handleCreateIncident() {
  createIncidentLoading.value = true
  try {
    await incidentApi.create(newIncident.value)
    newIncident.value = { title: '', description: '', severity: 'medium' }
    incidents.value = await incidentApi.list()
  } catch (e) {
    console.error('Failed to create incident:', e)
  } finally {
    createIncidentLoading.value = false
  }
}

async function handleIncidentStatus(id: string, status: string) {
  try {
    await incidentApi.update(id, { status })
    incidents.value = await incidentApi.list()
  } catch (e) {
    console.error('Failed to update incident:', e)
  }
}

async function handleExport(type: string) {
  try {
    const result = await adminApi.exportData(type)
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `cyberwatch_${type}_${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  } catch (e) {
    console.error('Export failed:', e)
  }
}

function copyKey() {
  navigator.clipboard.writeText(createdKey.value)
}

function formatDate(s: string) {
  if (!s) return '-'
  return new Date(s).toLocaleString('id-ID', { dateStyle: 'short', timeStyle: 'short' })
}

const roleColors: Record<string, string> = {
  admin: 'bg-red-500/15 text-red-400 border-red-500/30',
  analyst: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  viewer: 'bg-gray-500/15 text-gray-400 border-gray-500/30'
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30'
}

const statusColors: Record<string, string> = {
  open: 'bg-red-500/15 text-red-400 border-red-500/30',
  investigating: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  resolved: 'bg-green-500/15 text-green-400 border-green-500/30',
  closed: 'bg-gray-500/15 text-gray-400 border-gray-500/30'
}
</script>

<template>
  <div class="space-y-4">
    <!-- Admin Tabs -->
    <div class="flex items-center gap-1 border-b border-cyber-border pb-2 overflow-x-auto">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeAdminTab = tab.id"
        :class="[
          'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors',
          activeAdminTab === tab.id
            ? 'bg-cyber-accent/15 text-cyber-accent'
            : 'text-cyber-textdim hover:text-cyber-text hover:bg-cyber-border/30'
        ]"
      >
        <svg viewBox="0 0 24 24" class="w-4 h-4 fill-none stroke-current stroke-width-2" stroke-linecap="round" stroke-linejoin="round">
          <path :d="tab.icon" />
        </svg>
        {{ tab.label }}
      </button>
    </div>

    <!-- Users Tab -->
    <div v-if="activeAdminTab === 'users'" class="space-y-4">
      <!-- Create user -->
      <div class="bg-cyber-card border border-cyber-border rounded-lg p-4">
        <h3 class="text-sm font-semibold text-cyber-text mb-3">Tambah User Baru</h3>
        <form @submit.prevent="handleCreateUser" class="grid grid-cols-1 md:grid-cols-4 gap-3">
          <input v-model="newUser.name" type="text" placeholder="Nama" class="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text focus:border-cyber-accent focus:outline-none" required />
          <input v-model="newUser.email" type="email" placeholder="Email" class="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text focus:border-cyber-accent focus:outline-none" required />
          <input v-model="newUser.password" type="password" placeholder="Password (min. 8 karakter)" minlength="8" maxlength="128" class="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text focus:border-cyber-accent focus:outline-none" required />
          <div class="flex gap-2">
            <select v-model="newUser.role" class="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text focus:border-cyber-accent focus:outline-none">
              <option value="viewer">Viewer</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
            <button type="submit" :disabled="createUserLoading" class="px-4 py-2 bg-cyber-accent text-white rounded-md text-sm font-medium hover:bg-cyber-accent/90 disabled:opacity-50">
              {{ createUserLoading ? '...' : '+' }}
            </button>
          </div>
        </form>
        <p v-if="createUserMsg" class="text-xs mt-2" :class="createUserMsg.includes('berhasil') ? 'text-green-400' : 'text-red-400'">{{ createUserMsg }}</p>
        <p v-if="orgInfo" class="text-xs text-cyber-textmuted mt-2">{{ users.length }} / {{ orgInfo.max_users }} user digunakan</p>
      </div>

      <!-- User list -->
      <div class="bg-cyber-card border border-cyber-border rounded-lg overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-cyber-border text-cyber-textdim text-xs">
              <th class="text-left p-3 font-medium">Nama</th>
              <th class="text-left p-3 font-medium">Email</th>
              <th class="text-left p-3 font-medium">Role</th>
              <th class="text-left p-3 font-medium">Status</th>
              <th class="text-left p-3 font-medium">Last Login</th>
              <th class="text-right p-3 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="u in users" :key="u.id" class="border-b border-cyber-border/50 hover:bg-cyber-border/10">
              <td class="p-3 text-cyber-text">{{ u.name }}</td>
              <td class="p-3 text-cyber-textdim font-mono text-xs">{{ u.email }}</td>
              <td class="p-3">
                <select
                  :value="u.role"
                  @change="handleRoleChange(u.id, ($event.target as HTMLSelectElement).value)"
                  :class="['px-2 py-0.5 rounded text-xs border font-medium cursor-pointer', roleColors[u.role] || roleColors.viewer]"
                >
                  <option value="viewer">Viewer</option>
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </td>
              <td class="p-3">
                <button
                  @click="handleToggleStatus(u.id, u.status)"
                  :class="['px-2 py-0.5 rounded text-xs border font-medium', u.status === 'active' ? 'bg-green-500/15 text-green-400 border-green-500/30' : 'bg-red-500/15 text-red-400 border-red-500/30']"
                >
                  {{ u.status === 'active' ? 'Active' : 'Disabled' }}
                </button>
              </td>
              <td class="p-3 text-cyber-textdim text-xs font-mono">{{ formatDate(u.last_login) }}</td>
              <td class="p-3 text-right">
                <button @click="handleDeleteUser(u.id, u.name)" class="text-xs text-red-400 hover:text-red-300 px-2">Delete</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Organization Tab -->
    <div v-if="activeAdminTab === 'org' && orgInfo" class="space-y-4">
      <div class="bg-cyber-card border border-cyber-border rounded-lg p-6">
        <h3 class="text-sm font-semibold text-cyber-text mb-4">Informasi Organisasi</h3>
        <div class="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label class="text-xs text-cyber-textmuted">Nama Organisasi</label>
            <p class="text-sm text-cyber-text font-medium">{{ orgInfo.name }}</p>
          </div>
          <div>
            <label class="text-xs text-cyber-textmuted">Plan</label>
            <span class="inline-block px-2 py-0.5 bg-cyber-accent/15 text-cyber-accent text-xs rounded font-medium uppercase">{{ orgInfo.plan }}</span>
          </div>
          <div>
            <label class="text-xs text-cyber-textmuted">Slug</label>
            <p class="text-sm text-cyber-textdim font-mono">{{ orgInfo.slug }}</p>
          </div>
          <div>
            <label class="text-xs text-cyber-textmuted">Max Users</label>
            <p class="text-sm text-cyber-text">{{ orgInfo.max_users }}</p>
          </div>
          <div>
            <label class="text-xs text-cyber-textmuted">Dibuat</label>
            <p class="text-sm text-cyber-textdim">{{ formatDate(orgInfo.created_at) }}</p>
          </div>
          <div>
            <label class="text-xs text-cyber-textmuted">Active Users</label>
            <p class="text-sm text-cyber-text">{{ orgInfo.userCount }} / {{ orgInfo.max_users }}</p>
          </div>
        </div>
      </div>
    </div>

    <!-- API Keys Tab -->
    <div v-if="activeAdminTab === 'apikeys'" class="space-y-4">
      <div class="bg-cyber-card border border-cyber-border rounded-lg p-4">
        <h3 class="text-sm font-semibold text-cyber-text mb-3">Buat API Key Baru</h3>
        <form @submit.prevent="handleCreateKey" class="flex gap-3">
          <input v-model="newKeyName" type="text" placeholder="Nama API Key (mis: SIEM Integration)" class="flex-1 px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text focus:border-cyber-accent focus:outline-none" required />
          <select v-model="newKeyPerms" class="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text">
            <option value="read">Read Only</option>
            <option value="read-write">Read & Write</option>
          </select>
          <button type="submit" :disabled="createKeyLoading" class="px-4 py-2 bg-cyber-accent text-white rounded-md text-sm font-medium hover:bg-cyber-accent/90 disabled:opacity-50">
            {{ createKeyLoading ? '...' : 'Generate' }}
          </button>
        </form>
        <div v-if="createdKey" class="mt-3 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-md">
          <p class="text-xs text-yellow-400 mb-1 font-medium">API Key berhasil dibuat. Simpan key ini dengan aman — tidak akan ditampilkan lagi!</p>
          <div class="flex gap-2">
            <code class="flex-1 px-3 py-2 bg-cyber-bg rounded text-xs text-cyber-accent font-mono break-all">{{ createdKey }}</code>
            <button @click="copyKey" class="px-3 py-1 bg-cyber-accent/20 text-cyber-accent rounded text-xs hover:bg-cyber-accent/30">Copy</button>
          </div>
        </div>
      </div>

      <div class="bg-cyber-card border border-cyber-border rounded-lg overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-cyber-border text-cyber-textdim text-xs">
              <th class="text-left p-3 font-medium">Nama</th>
              <th class="text-left p-3 font-medium">Key</th>
              <th class="text-left p-3 font-medium">Permissions</th>
              <th class="text-left p-3 font-medium">Last Used</th>
              <th class="text-left p-3 font-medium">Status</th>
              <th class="text-right p-3 font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="k in apiKeys" :key="k.key_id" class="border-b border-cyber-border/50">
              <td class="p-3 text-cyber-text">{{ k.name }}</td>
              <td class="p-3 text-cyber-textdim font-mono text-xs">{{ k.key_prefix }}</td>
              <td class="p-3 text-cyber-textdim text-xs">{{ k.permissions }}</td>
              <td class="p-3 text-cyber-textdim text-xs font-mono">{{ formatDate(k.last_used) }}</td>
              <td class="p-3">
                <span :class="['px-2 py-0.5 rounded text-xs border', k.revoked ? 'bg-red-500/15 text-red-400 border-red-500/30' : 'bg-green-500/15 text-green-400 border-green-500/30']">
                  {{ k.revoked ? 'Revoked' : 'Active' }}
                </span>
              </td>
              <td class="p-3 text-right">
                <button v-if="!k.revoked" @click="handleRevokeKey(k.key_id)" class="text-xs text-red-400 hover:text-red-300 px-2">Revoke</button>
              </td>
            </tr>
            <tr v-if="apiKeys.length === 0">
              <td colspan="6" class="p-8 text-center text-cyber-textmuted text-sm">Belum ada API key. Buat di atas untuk integrasi eksternal.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Incidents Tab -->
    <div v-if="activeAdminTab === 'incidents'" class="space-y-4">
      <div class="bg-cyber-card border border-cyber-border rounded-lg p-4">
        <h3 class="text-sm font-semibold text-cyber-text mb-3">Lapor Incident Baru</h3>
        <form @submit.prevent="handleCreateIncident" class="space-y-3">
          <input v-model="newIncident.title" type="text" placeholder="Judul incident" class="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text focus:border-cyber-accent focus:outline-none" required />
          <textarea v-model="newIncident.description" placeholder="Deskripsi..." rows="2" class="w-full px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text focus:border-cyber-accent focus:outline-none"></textarea>
          <div class="flex gap-3">
            <select v-model="newIncident.severity" class="px-3 py-2 bg-cyber-bg border border-cyber-border rounded-md text-sm text-cyber-text">
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <button type="submit" :disabled="createIncidentLoading" class="px-4 py-2 bg-cyber-accent text-white rounded-md text-sm font-medium hover:bg-cyber-accent/90 disabled:opacity-500">
              {{ createIncidentLoading ? '...' : 'Buat Incident' }}
            </button>
          </div>
        </form>
      </div>

      <div class="space-y-2">
        <div v-for="inc in incidents" :key="inc.id" class="bg-cyber-card border border-cyber-border rounded-lg p-4">
          <div class="flex items-start justify-between mb-2">
            <div class="flex-1">
              <div class="flex items-center gap-2 mb-1">
                <span :class="['px-2 py-0.5 rounded text-xs border font-medium', severityColors[inc.severity] || severityColors.medium]">{{ inc.severity }}</span>
                <select
                  :value="inc.status"
                  @change="handleIncidentStatus(inc.id, ($event.target as HTMLSelectElement).value)"
                  :class="['px-2 py-0.5 rounded text-xs border font-medium cursor-pointer', statusColors[inc.status] || statusColors.open]"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
              </div>
              <h4 class="text-sm font-semibold text-cyber-text">{{ inc.title }}</h4>
              <p v-if="inc.description" class="text-xs text-cyber-textdim mt-1">{{ inc.description }}</p>
              <p class="text-xs text-cyber-textmuted mt-1 font-mono">{{ formatDate(inc.created_at) }}</p>
            </div>
          </div>
        </div>
        <p v-if="incidents.length === 0" class="text-center text-cyber-textmuted text-sm py-8">Belum ada incident.</p>
      </div>
    </div>

    <!-- Audit Logs Tab -->
    <div v-if="activeAdminTab === 'audit'" class="bg-cyber-card border border-cyber-border rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-cyber-border text-cyber-textdim text-xs">
            <th class="text-left p-3 font-medium">Waktu</th>
            <th class="text-left p-3 font-medium">User</th>
            <th class="text-left p-3 font-medium">Action</th>
            <th class="text-left p-3 font-medium">Resource</th>
            <th class="text-left p-3 font-medium">Details</th>
            <th class="text-left p-3 font-medium">IP</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="log in auditLogs" :key="log.id" class="border-b border-cyber-border/50 hover:bg-cyber-border/10">
            <td class="p-3 text-cyber-textdim text-xs font-mono">{{ formatDate(log.timestamp) }}</td>
            <td class="p-3 text-cyber-textdim text-xs">{{ log.user_email }}</td>
            <td class="p-3"><code class="text-cyber-accent text-xs">{{ log.action }}</code></td>
            <td class="p-3 text-cyber-textdim text-xs">{{ log.resource }}</td>
            <td class="p-3 text-cyber-textmuted text-xs font-mono max-w-xs truncate">{{ log.details }}</td>
            <td class="p-3 text-cyber-textmuted text-xs font-mono">{{ log.ip_address }}</td>
          </tr>
          <tr v-if="auditLogs.length === 0">
            <td colspan="6" class="p-8 text-center text-cyber-textmuted text-sm">Belum ada audit log.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Export Tab -->
    <div v-if="activeAdminTab === 'export'" class="space-y-3">
      <div class="bg-cyber-card border border-cyber-border rounded-lg p-6">
        <h3 class="text-sm font-semibold text-cyber-text mb-4">Export Data Organisasi</h3>
        <p class="text-xs text-cyber-textmuted mb-4">Download data dalam format JSON untuk backup atau integrasi dengan SIEM/SOAR eksternal.</p>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <button @click="handleExport('events')" class="p-4 bg-cyber-bg border border-cyber-border rounded-lg hover:border-cyber-accent transition-colors text-center">
            <svg viewBox="0 0 24 24" class="w-6 h-6 mx-auto mb-2 fill-none stroke-current stroke-cyber-accent stroke-width-2"><path d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" stroke-linecap="round" stroke-linejoin="round"/></svg>
            <p class="text-sm font-medium text-cyber-text">Security Events</p>
          </button>
          <button @click="handleExport('alerts')" class="p-4 bg-cyber-bg border border-cyber-border rounded-lg hover:border-cyber-accent transition-colors text-center">
            <svg viewBox="0 0 24 24" class="w-6 h-6 mx-auto mb-2 fill-none stroke-current stroke-cyber-accent stroke-width-2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" stroke-linecap="round" stroke-linejoin="round"/></svg>
            <p class="text-sm font-medium text-cyber-text">Alerts</p>
          </button>
          <button @click="handleExport('incidents')" class="p-4 bg-cyber-bg border border-cyber-border rounded-lg hover:border-cyber-accent transition-colors text-center">
            <svg viewBox="0 0 24 24" class="w-6 h-6 mx-auto mb-2 fill-none stroke-current stroke-cyber-accent stroke-width-2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" stroke-linecap="round" stroke-linejoin="round"/></svg>
            <p class="text-sm font-medium text-cyber-text">Incidents</p>
          </button>
          <button @click="handleExport('audit')" class="p-4 bg-cyber-bg border border-cyber-border rounded-lg hover:border-cyber-accent transition-colors text-center">
            <svg viewBox="0 0 24 24" class="w-6 h-6 mx-auto mb-2 fill-none stroke-current stroke-cyber-accent stroke-width-2"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" stroke-linecap="round" stroke-linejoin="round"/></svg>
            <p class="text-sm font-medium text-cyber-text">Audit Logs</p>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
