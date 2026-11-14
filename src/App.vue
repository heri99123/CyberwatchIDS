<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useStore } from '@/composables/useStore'
import { getToken, getStoredUser, clearToken } from '@/api/client'
import DashboardView from '@/views/DashboardView.vue'
import EventsView from '@/views/EventsView.vue'
import RulesView from '@/views/RulesView.vue'
import IPReputationView from '@/views/IPReputationView.vue'
import AlertsView from '@/views/AlertsView.vue'
import CVEView from '@/views/CVEView.vue'
import SimulatorView from '@/views/SimulatorView.vue'
import AuthView from '@/views/AuthView.vue'
import AdminView from '@/views/AdminView.vue'

const { state, loadStats, loadInitialFeed, initWebSocket, destroy } = useStore()

const activeTab = ref('dashboard')
const isAuthenticated = ref(false)
const currentUser = ref(getStoredUser())

const tabs = [
  { id: 'dashboard', label: 'Dashboard', icon: 'M3 12l9-9 9 9M5 10v10h14V10', adminOnly: false },
  { id: 'events', label: 'Events', icon: 'M4 6h16M4 12h16M4 18h16', adminOnly: false },
  { id: 'alerts', label: 'Alerts', icon: 'M12 2L1 21h22L12 2zM12 9v4M12 17h.01', adminOnly: false },
  { id: 'cve', label: 'CVE Database', icon: 'M4 4h16v16H4zM4 9h16M9 4v16', adminOnly: false },
  { id: 'rules', label: 'IDS Rules', icon: 'M12 2v20M2 12h20M5 5l14 14M19 5L5 19', adminOnly: false },
  { id: 'iprep', label: 'IP Reputation', icon: 'M12 2a10 10 0 100 20 10 10 0 000-20zM2 12h20', adminOnly: false },
  { id: 'simulator', label: 'Simulator', icon: 'M13 10V3L4 14h7v7l9-11h-7z', adminOnly: false },
  { id: 'admin', label: 'Backoffice', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z', adminOnly: true }
]

const visibleTabs = ref(tabs)

function checkAuth() {
  const token = getToken()
  if (token) {
    isAuthenticated.value = true
    currentUser.value = getStoredUser()
    // Filter tabs based on role
    if (currentUser.value?.role === 'admin') {
      visibleTabs.value = tabs
    } else {
      visibleTabs.value = tabs.filter(t => !t.adminOnly)
    }
  } else {
    isAuthenticated.value = false
    visibleTabs.value = tabs.filter(t => !t.adminOnly)
  }
}

function onAuthSuccess() {
  checkAuth()
  activeTab.value = 'dashboard'
  loadStats()
  loadInitialFeed()
  initWebSocket()
}

function handleLogout() {
  clearToken()
  isAuthenticated.value = false
  currentUser.value = null
  destroy()
}

onMounted(() => {
  checkAuth()
  if (isAuthenticated.value) {
    loadStats()
    loadInitialFeed()
    initWebSocket()
    const poll = setInterval(loadStats, 10000)
    onUnmounted(() => clearInterval(poll))
  }
})

onUnmounted(() => destroy())
</script>

<template>
  <!-- Auth screen -->
  <AuthView v-if="!isAuthenticated" @auth-success="onAuthSuccess" />

  <!-- Main app -->
  <div v-else class="min-h-screen flex flex-col">
    <!-- Topbar -->
    <header class="flex items-center justify-between px-4 h-14 border-b border-cyber-border bg-cyber-card/80 backdrop-blur-sm sticky top-0 z-30">
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-2">
          <svg viewBox="0 0 32 32" class="w-7 h-7">
            <path d="M16 4 L26 9 V16 C26 21 22 25 16 27 C10 25 6 21 6 16 V9 Z" stroke="#00d9ff" stroke-width="1.5" fill="none"/>
            <circle cx="16" cy="15" r="3" fill="#00d9ff" opacity="0.8"/>
          </svg>
          <div class="flex flex-col leading-none">
            <span class="text-sm font-bold tracking-tight">CyberWatch IDS</span>
            <span v-if="currentUser" class="text-[10px] text-cyber-textmuted">{{ currentUser.orgName }}</span>
          </div>
        </div>
      </div>

      <div class="flex items-center gap-4">
        <span v-if="state.wsConnected" class="live-dot">Connected</span>
        <span v-else class="text-[11px] text-cyber-textmuted">Reconnecting…</span>
        
        <!-- User menu -->
        <div class="flex items-center gap-3 border-l border-cyber-border pl-4">
          <div class="flex flex-col items-end leading-none">
            <span class="text-xs font-medium text-cyber-text">{{ currentUser?.name }}</span>
            <span class="text-[10px] text-cyber-textmuted">{{ currentUser?.email }}</span>
          </div>
          <div class="w-8 h-8 rounded-full bg-cyber-accent/20 flex items-center justify-center text-cyber-accent text-xs font-bold">
            {{ currentUser?.name?.charAt(0)?.toUpperCase() || 'U' }}
          </div>
          <button @click="handleLogout" class="text-xs text-cyber-textdim hover:text-red-400 transition-colors px-2 py-1 rounded hover:bg-red-500/10">
            Logout
          </button>
        </div>
      </div>
    </header>

    <!-- Nav -->
    <nav class="flex items-center gap-1 px-4 h-11 border-b border-cyber-border bg-cyber-card/50 overflow-x-auto">
      <button
        v-for="tab in visibleTabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        :class="[
          'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium whitespace-nowrap transition-colors',
          activeTab === tab.id
            ? 'bg-cyber-accent/15 text-cyber-accent'
            : 'text-cyber-textdim hover:text-cyber-text hover:bg-cyber-border/30'
        ]"
      >
        <svg viewBox="0 0 24 24" class="w-4 h-4 fill-none stroke-current stroke-width-2" stroke-linecap="round" stroke-linejoin="round">
          <path :d="tab.icon" />
        </svg>
        {{ tab.label }}
      </button>
    </nav>

    <!-- Content -->
    <main class="flex-1 overflow-auto p-4">
      <DashboardView v-if="activeTab === 'dashboard'" />
      <EventsView v-else-if="activeTab === 'events'" />
      <AlertsView v-else-if="activeTab === 'alerts'" />
      <CVEView v-else-if="activeTab === 'cve'" />
      <RulesView v-else-if="activeTab === 'rules'" />
      <IPReputationView v-else-if="activeTab === 'iprep'" />
      <SimulatorView v-else-if="activeTab === 'simulator'" />
      <AdminView v-else-if="activeTab === 'admin'" @logout="handleLogout" />
    </main>
  </div>
</template>
