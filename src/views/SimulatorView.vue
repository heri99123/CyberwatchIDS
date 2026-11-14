<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import { useStore } from '@/composables/useStore'

const { loadStats } = useStore()

const running = ref(false)
const interval = ref(3000)
const attackTypes = ref<string[]>([])
const lastFired = ref<string>('')

async function checkStatus() {
  try {
    const s = await api.getSimulatorStatus()
    running.value = s.running
  } catch (e) {
    console.error(e)
  }
}

async function start() {
  try {
    await api.startSimulator(interval.value)
    running.value = true
  } catch (e) {
    console.error(e)
  }
}

async function stop() {
  try {
    await api.stopSimulator()
    running.value = false
  } catch (e) {
    console.error(e)
  }
}

async function inject(type: string) {
  try {
    await api.injectAttack(type)
    lastFired.value = type + ' at ' + new Date().toLocaleTimeString('id-ID')
    loadStats()
  } catch (e) {
    console.error(e)
  }
}

async function resetData() {
  if (!confirm('This will purge ALL events, alerts, and IP reputation data. CVE entries and rules will be preserved. Continue?')) return
  try {
    await api.resetData()
    loadStats()
  } catch (e) {
    console.error(e)
  }
}

onMounted(async () => {
  await checkStatus()
  // Fetch attack types from rules
  try {
    const rules = await api.getRules()
    attackTypes.value = [...new Set(rules.map(r => r.attack_type))].sort()
  } catch (e) {
    console.error(e)
  }
})
</script>

<template>
  <div class="space-y-4 animate-fade-in">
    <!-- Simulator Control -->
    <div class="card">
      <div class="card-header">
        <h2 class="text-sm font-semibold">Attack Simulator</h2>
        <span v-if="running" class="live-dot text-cyber-high">Running</span>
        <span v-else class="text-[11px] text-cyber-textmuted">Stopped</span>
      </div>
      <div class="card-body space-y-4">
        <div class="flex items-center gap-3">
          <label class="text-sm text-cyber-textdim">Interval:</label>
          <select v-model="interval" class="input" :disabled="running">
            <option :value="1000">1 second</option>
            <option :value="2000">2 seconds</option>
            <option :value="3000">3 seconds</option>
            <option :value="5000">5 seconds</option>
            <option :value="10000">10 seconds</option>
          </select>
          <button v-if="!running" class="btn btn-primary" @click="start">Start Simulation</button>
          <button v-else class="btn btn-danger" @click="stop">Stop</button>
        </div>
        <div v-if="lastFired" class="text-xs text-cyber-textmuted">
          Last fired: {{ lastFired }}
        </div>
      </div>
    </div>

    <!-- Manual Attack Injection -->
    <div class="card">
      <div class="card-header">
        <h2 class="text-sm font-semibold">Manual Attack Injection</h2>
        <span class="text-[11px] text-cyber-textmuted">{{ attackTypes.length }} attack types</span>
      </div>
      <div class="card-body">
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
          <button
            v-for="type in attackTypes"
            :key="type"
            class="btn btn-ghost border border-cyber-border justify-start text-xs"
            @click="inject(type)"
          >
            {{ type }}
          </button>
        </div>
      </div>
    </div>

    <!-- Maintenance -->
    <div class="card">
      <div class="card-header">
        <h2 class="text-sm font-semibold">Maintenance</h2>
      </div>
      <div class="card-body">
        <div class="flex items-center gap-3">
          <button class="btn btn-danger" @click="resetData">
            Reset Event Data
          </button>
          <span class="text-xs text-cyber-textmuted">Purges all events, alerts, and IP reputation. Keeps CVE entries and rules.</span>
        </div>
      </div>
    </div>
  </div>
</template>
