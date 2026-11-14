<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import type { SecurityEvent } from '@/api/types'

const events = ref<SecurityEvent[]>([])
const loading = ref(false)
const filters = ref({
  severity: '',
  attack_type: '',
  source_ip: ''
})

async function load() {
  loading.value = true
  try {
    if (filters.value.severity || filters.value.attack_type || filters.value.source_ip) {
      events.value = await api.searchEvents(filters.value)
    } else {
      events.value = await api.getEvents(100)
    }
  } catch (e) {
    console.error(e)
  }
  loading.value = false
}

function reset() {
  filters.value = { severity: '', attack_type: '', source_ip: '' }
  load()
}

function getSeverityClass(sev: string) {
  return `badge-${(sev || 'info').toLowerCase()}`
}

function formatTime(ts: string) {
  if (!ts) return ''
  return new Date(ts).toLocaleString('id-ID')
}

onMounted(load)
</script>

<template>
  <div class="space-y-4 animate-fade-in">
    <div class="card">
      <div class="card-header">
        <h2 class="text-sm font-semibold">Security Events</h2>
        <span class="text-[11px] text-cyber-textmuted">{{ events.length }} results</span>
      </div>
      <div class="card-body">
        <!-- Filters -->
        <div class="flex flex-wrap gap-2 mb-3">
          <select v-model="filters.severity" class="input" @change="load">
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <input v-model="filters.attack_type" class="input" placeholder="Attack type…" @keyup.enter="load" />
          <input v-model="filters.source_ip" class="input" placeholder="Source IP…" @keyup.enter="load" />
          <button class="btn btn-primary" @click="load">Search</button>
          <button class="btn btn-ghost" @click="reset">Reset</button>
        </div>

        <!-- Table -->
        <div class="overflow-x-auto max-h-[600px] overflow-y-auto rounded border border-cyber-border">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Attack Type</th>
                <th>Rule</th>
                <th>Source IP</th>
                <th>Path</th>
                <th>Action</th>
                <th>CVE</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="evt in events" :key="evt.id">
                <td class="font-mono text-xs whitespace-nowrap">{{ formatTime(evt.timestamp) }}</td>
                <td><span class="badge" :class="getSeverityClass(evt.severity)">{{ evt.severity }}</span></td>
                <td class="text-xs">{{ evt.attack_type }}</td>
                <td class="text-xs max-w-xs truncate" :title="evt.rule_name">{{ evt.rule_name }}</td>
                <td class="font-mono text-xs">{{ evt.source_ip }}</td>
                <td class="font-mono text-xs max-w-xs truncate" :title="evt.path">{{ evt.path }}</td>
                <td>
                  <span v-if="evt.blocked" class="badge badge-critical">Blocked</span>
                  <span v-else class="badge badge-info">{{ evt.action }}</span>
                </td>
                <td class="font-mono text-xs text-cyber-accent">{{ evt.matched_cve || '—' }}</td>
              </tr>
              <tr v-if="events.length === 0">
                <td colspan="8" class="text-center py-8 text-cyber-textmuted">No events found</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>
