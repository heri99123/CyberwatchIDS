<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import type { IPReputation } from '@/api/types'

const ips = ref<IPReputation[]>([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    ips.value = await api.getIPReputation()
  } catch (e) {
    console.error(e)
  }
  loading.value = false
}

async function block(ip: string) {
  try {
    await api.blockIP(ip)
    ips.value = ips.value.map(i => i.ip_address === ip ? { ...i, blocked: 1 } : i)
  } catch (e) {
    console.error(e)
  }
}

async function unblock(ip: string) {
  try {
    await api.unblockIP(ip)
    ips.value = ips.value.map(i => i.ip_address === ip ? { ...i, blocked: 0 } : i)
  } catch (e) {
    console.error(e)
  }
}

function threatColor(level: string): string {
  const map: Record<string, string> = {
    critical: '#ff3838',
    high: '#ffa502',
    medium: '#ffd32a',
    low: '#26de81'
  }
  return map[level] || '#00d9ff'
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
        <h2 class="text-sm font-semibold">IP Reputation</h2>
        <div class="flex items-center gap-2">
          <span class="text-[11px] text-cyber-textmuted">{{ ips.length }} IPs tracked</span>
          <button class="btn btn-primary text-xs" @click="load">Refresh</button>
        </div>
      </div>
      <div class="card-body">
        <div class="overflow-x-auto rounded border border-cyber-border">
          <table class="cyber-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Score</th>
                <th>Threat Level</th>
                <th>Events</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="ip in ips" :key="ip.ip_address">
                <td class="font-mono text-xs">{{ ip.ip_address }}</td>
                <td>
                  <div class="flex items-center gap-2">
                    <div class="w-16 h-1.5 bg-cyber-border rounded-full overflow-hidden">
                      <div
                        class="h-full rounded-full transition-all duration-500"
                        :style="{ width: ip.reputation_score + '%', backgroundColor: threatColor(ip.threat_level) }"
                      />
                    </div>
                    <span class="text-xs font-mono">{{ ip.reputation_score }}</span>
                  </div>
                </td>
                <td>
                  <span class="badge" :style="{ backgroundColor: threatColor(ip.threat_level) + '22', color: threatColor(ip.threat_level) }">
                    {{ ip.threat_level }}
                  </span>
                </td>
                <td class="text-xs">{{ ip.total_events }}</td>
                <td class="font-mono text-[11px] text-cyber-textdim whitespace-nowrap">{{ formatTime(ip.first_seen) }}</td>
                <td class="font-mono text-[11px] text-cyber-textdim whitespace-nowrap">{{ formatTime(ip.last_seen) }}</td>
                <td>
                  <span v-if="ip.blocked" class="badge badge-critical">Blocked</span>
                  <span v-else class="badge badge-low">Active</span>
                </td>
                <td>
                  <button v-if="!ip.blocked" class="btn btn-danger text-xs" @click="block(ip.ip_address)">Block</button>
                  <button v-else class="btn btn-ghost text-xs" @click="unblock(ip.ip_address)">Unblock</button>
                </td>
              </tr>
              <tr v-if="ips.length === 0">
                <td colspan="8" class="text-center py-8 text-cyber-textmuted">No IP reputation data</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</template>
