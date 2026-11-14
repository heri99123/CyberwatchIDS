<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import type { Alert } from '@/api/types'

const alerts = ref<Alert[]>([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    alerts.value = await api.getAlerts(false)
  } catch (e) {
    console.error(e)
  }
  loading.value = false
}

async function ack(id: number) {
  try {
    await api.acknowledgeAlert(id)
    alerts.value = alerts.value.map(a => a.id === id ? { ...a, acknowledged: 1 } : a)
  } catch (e) {
    console.error(e)
  }
}

async function ackAll() {
  const unack = alerts.value.filter(a => !a.acknowledged)
  for (const a of unack) {
    await ack(a.id)
  }
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
        <h2 class="text-sm font-semibold">Security Alerts</h2>
        <div class="flex gap-2 items-center">
          <span class="text-[11px] text-cyber-textmuted">{{ alerts.filter(a => !a.acknowledged).length }} unacknowledged</span>
          <button class="btn btn-ghost text-xs" @click="ackAll" v-if="alerts.some(a => !a.acknowledged)">Ack All</button>
          <button class="btn btn-primary text-xs" @click="load">Refresh</button>
        </div>
      </div>
      <div class="card-body max-h-[600px] overflow-y-auto">
        <div v-if="alerts.length === 0" class="text-center py-8 text-cyber-textmuted text-sm">
          No alerts
        </div>
        <div v-else class="space-y-2">
          <div
            v-for="alert in alerts"
            :key="alert.id"
            class="flex items-start gap-3 p-3 rounded border-l-2 transition-opacity"
            :class="{
              'border-cyber-critical bg-cyber-critical/5': alert.alert_type?.includes('Critical') || alert.message?.includes('CRITICAL'),
              'border-cyber-high bg-cyber-high/5': !(alert.alert_type?.includes('Critical') || alert.message?.includes('CRITICAL')),
              'opacity-45': alert.acknowledged
            }"
          >
            <div class="flex-1">
              <div class="text-sm text-cyber-text">{{ alert.message }}</div>
              <div class="text-xs text-cyber-textmuted mt-1">
                {{ formatTime(alert.alert_time) }} · {{ alert.alert_type }}
                <span v-if="alert.acknowledged" class="ml-2 text-cyber-low">· Acked by {{ alert.acknowledged_by }}</span>
              </div>
            </div>
            <button v-if="!alert.acknowledged" class="btn btn-ghost text-xs" @click="ack(alert.id)">Acknowledge</button>
            <span v-else class="badge badge-low">Done</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
