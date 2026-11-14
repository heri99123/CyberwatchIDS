<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts'
import { useStore } from '@/composables/useStore'
import { api } from '@/api/client'
import type { SecurityEvent, CVEEntry } from '@/api/types'

const { state } = useStore()

// Chart refs
const timelineRef = ref<HTMLDivElement>()
const attackTypesRef = ref<HTMLDivElement>()
const severityRef = ref<HTMLDivElement>()
const topAttackersRef = ref<HTMLDivElement>()

let timelineChart: echarts.ECharts | null = null
let attackTypesChart: echarts.ECharts | null = null
let severityChart: echarts.ECharts | null = null
let topAttackersChart: echarts.ECharts | null = null

// Additional data
const cveRefs = ref<CVEEntry[]>([])

const severityColors: Record<string, string> = {
  CRITICAL: '#ff3838',
  HIGH: '#ffa502',
  MEDIUM: '#ffd32a',
  LOW: '#26de81',
  INFO: '#00d9ff'
}

const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

function initCharts() {
  if (timelineRef.value) timelineChart = echarts.init(timelineRef.value, 'dark')
  if (attackTypesRef.value) attackTypesChart = echarts.init(attackTypesRef.value, 'dark')
  if (severityRef.value) severityChart = echarts.init(severityRef.value, 'dark')
  if (topAttackersRef.value) topAttackersChart = echarts.init(topAttackersRef.value, 'dark')
}

function updateCharts() {
  if (!state.stats) return

  // Timeline chart
  if (timelineChart) {
    const buckets = state.stats.recentEvents || []
    const hours: string[] = []
    const counts: number[] = []
    // Build 24-hour buckets, oldest first
    const now = new Date()
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 3600000)
      const key = d.toISOString().slice(0, 13).replace('T', ' ') + ':00:00'
      const found = buckets.find(b => b.hour === key)
      hours.push(d.getHours().toString().padStart(2, '0') + ':00')
      counts.push(found ? found.count : 0)
    }

    timelineChart.setOption({
      backgroundColor: 'transparent',
      grid: { left: 40, right: 15, top: 20, bottom: 30 },
      tooltip: {
        trigger: 'axis',
        backgroundColor: 'rgba(10,14,20,0.95)',
        borderColor: '#1e2a3a',
        textStyle: { color: '#e0e6ed' },
        formatter: (params: any) => {
          const p = params[0]
          return `${p.axisValue}<br/>${p.marker} Events: <b>${p.value}</b>`
        }
      },
      xAxis: {
        type: 'category',
        data: hours,
        axisLine: { lineStyle: { color: '#2a3a4f' } },
        axisLabel: { color: '#5a6a7e', fontSize: 10, interval: 2 },
        axisTick: { show: false }
      },
      yAxis: {
        type: 'value',
        axisLine: { show: false },
        axisLabel: { color: '#5a6a7e', fontSize: 10 },
        splitLine: { lineStyle: { color: '#1e2a3a', type: 'dashed' } }
      },
      series: [{
        name: 'Events',
        type: 'bar',
        data: counts,
        itemStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: '#00d9ff' },
            { offset: 1, color: '#0099b8' }
          ]),
          borderRadius: [3, 3, 0, 0]
        },
        emphasis: { itemStyle: { color: '#00d9ff' } },
        animationDuration: 800,
        animationEasing: 'cubicOut'
      }]
    }, true)
  }

  // Attack types chart
  if (attackTypesChart) {
    const types = (state.stats.topAttackTypes || []).slice(0, 8)
    attackTypesChart.setOption({
      backgroundColor: 'transparent',
      grid: { left: 10, right: 30, top: 10, bottom: 10, containLabel: true },
      tooltip: {
        backgroundColor: 'rgba(10,14,20,0.95)',
        borderColor: '#1e2a3a',
        textStyle: { color: '#e0e6ed' }
      },
      xAxis: { type: 'value', axisLabel: { color: '#5a6a7e', fontSize: 10 }, splitLine: { lineStyle: { color: '#1e2a3a' } } },
      yAxis: {
        type: 'category',
        data: types.map(t => t.attack_type || 'Unknown').reverse(),
        axisLabel: { color: '#8a96a8', fontSize: 10 },
        axisLine: { lineStyle: { color: '#2a3a4f' } },
        axisTick: { show: false }
      },
      series: [{
        type: 'bar',
        data: types.map(t => t.count).reverse(),
        itemStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 1, 0, [
            { offset: 0, color: '#ffa502' },
            { offset: 1, color: '#ff3838' }
          ]),
          borderRadius: [0, 3, 3, 0]
        },
        label: { show: true, position: 'right', color: '#e0e6ed', fontSize: 10 },
        animationDuration: 600,
        animationEasing: 'elasticOut'
      }]
    }, true)
  }

  // Severity donut chart
  if (severityChart) {
    const s = state.stats
    const data = [
      { name: 'Critical', value: s.criticalEvents, itemStyle: { color: '#ff3838' } },
      { name: 'High', value: s.highEvents, itemStyle: { color: '#ffa502' } },
      { name: 'Medium', value: s.totalEvents - s.criticalEvents - s.highEvents, itemStyle: { color: '#ffd32a' } },
      { name: 'Low', value: 0, itemStyle: { color: '#26de81' } }
    ].filter(d => d.value > 0)

    severityChart.setOption({
      backgroundColor: 'transparent',
      tooltip: {
        backgroundColor: 'rgba(10,14,20,0.95)',
        borderColor: '#1e2a3a',
        textStyle: { color: '#e0e6ed' },
        formatter: '{b}: {c} ({d}%)'
      },
      legend: {
        bottom: 5,
        textStyle: { color: '#8a96a8', fontSize: 10 },
        itemWidth: 10,
        itemHeight: 10
      },
      series: [{
        type: 'pie',
        radius: ['40%', '65%'],
        center: ['50%', '40%'],
        avoidLabelOverlap: true,
        label: { show: false },
        emphasis: {
          scale: true,
          scaleSize: 8,
          label: { show: true, fontSize: 12, color: '#e0e6ed' }
        },
        data,
        animationDuration: 800,
        animationEasing: 'cubicOut'
      }]
    }, true)
  }

  // Top attackers chart
  if (topAttackersChart) {
    const attackers = (state.stats.topAttackers || []).slice(0, 8)
    topAttackersChart.setOption({
      backgroundColor: 'transparent',
      grid: { left: 10, right: 30, top: 10, bottom: 10, containLabel: true },
      tooltip: {
        backgroundColor: 'rgba(10,14,20,0.95)',
        borderColor: '#1e2a3a',
        textStyle: { color: '#e0e6ed' },
        formatter: (p: any) => `${p.name}<br/>Events: <b>${p.value}</b>`
      },
      xAxis: { type: 'value', axisLabel: { color: '#5a6a7e', fontSize: 10 }, splitLine: { lineStyle: { color: '#1e2a3a' } } },
      yAxis: {
        type: 'category',
        data: attackers.map(a => a.source_ip).reverse(),
        axisLabel: { color: '#8a96a8', fontSize: 10, fontFamily: 'monospace' },
        axisLine: { lineStyle: { color: '#2a3a4f' } },
        axisTick: { show: false }
      },
      series: [{
        type: 'bar',
        data: attackers.map(a => ({
          value: a.count,
          itemStyle: { color: severityColors[a.max_severity] || '#00d9ff', borderRadius: [0, 3, 3, 0] }
        })).reverse(),
        animationDuration: 600,
        animationEasing: 'elasticOut'
      }]
    }, true)
  }
}

function formatTime(ts: string): string {
  if (!ts) return ''
  const d = new Date(ts)
  return d.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function getSeverityClass(sev: string): string {
  return `badge-${(sev || 'info').toLowerCase()}`
}

// Load CVE references
async function loadCVERefs() {
  if (state.stats?.cveMatches?.length) {
    const ids = state.stats.cveMatches.map(m => m.matched_cve).filter(Boolean).slice(0, 10)
    const results: CVEEntry[] = []
    for (const id of ids) {
      try {
        const cve = await api.getCVEById(id)
        results.push(cve)
      } catch { /* skip */ }
    }
    cveRefs.value = results
  }
}

// Resize handler
function handleResize() {
  timelineChart?.resize()
  attackTypesChart?.resize()
  severityChart?.resize()
  topAttackersChart?.resize()
}

// Watch for stats changes to update charts
watch(() => state.stats, () => {
  nextTick(updateCharts)
  loadCVERefs()
}, { deep: true })

onMounted(async () => {
  await nextTick()
  initCharts()
  updateCharts()
  loadCVERefs()
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
  timelineChart?.dispose()
  attackTypesChart?.dispose()
  severityChart?.dispose()
  topAttackersChart?.dispose()
})
</script>

<template>
  <div class="space-y-4 animate-fade-in">
    <!-- Stats Cards -->
    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      <div class="card p-3 flex flex-col gap-1">
        <span class="text-[11px] text-cyber-textmuted uppercase tracking-wide">Total Events</span>
        <span class="text-2xl font-bold text-cyber-text">{{ state.stats?.totalEvents?.toLocaleString() || 0 }}</span>
      </div>
      <div class="card p-3 flex flex-col gap-1">
        <span class="text-[11px] text-cyber-textmuted uppercase tracking-wide">Blocked</span>
        <span class="text-2xl font-bold text-cyber-danger">{{ state.stats?.blockedEvents?.toLocaleString() || 0 }}</span>
      </div>
      <div class="card p-3 flex flex-col gap-1">
        <span class="text-[11px] text-cyber-textmuted uppercase tracking-wide">Critical</span>
        <span class="text-2xl font-bold text-cyber-critical">{{ state.stats?.criticalEvents?.toLocaleString() || 0 }}</span>
      </div>
      <div class="card p-3 flex flex-col gap-1">
        <span class="text-[11px] text-cyber-textmuted uppercase tracking-wide">High</span>
        <span class="text-2xl font-bold text-cyber-high">{{ state.stats?.highEvents?.toLocaleString() || 0 }}</span>
      </div>
      <div class="card p-3 flex flex-col gap-1">
        <span class="text-[11px] text-cyber-textmuted uppercase tracking-wide">Attackers</span>
        <span class="text-2xl font-bold text-cyber-accent">{{ state.stats?.uniqueAttackers || 0 }}</span>
      </div>
      <div class="card p-3 flex flex-col gap-1">
        <span class="text-[11px] text-cyber-textmuted uppercase tracking-wide">Active Alerts</span>
        <span class="text-2xl font-bold text-cyber-high">{{ state.stats?.activeAlerts?.toLocaleString() || 0 }}</span>
      </div>
    </div>

    <!-- Charts Row -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-4">
      <!-- Timeline -->
      <div class="card lg:col-span-2">
        <div class="card-header">
          <h2 class="text-sm font-semibold">Attack Timeline</h2>
          <span class="text-[11px] text-cyber-textmuted">Last 24 hours</span>
        </div>
        <div class="card-body" style="padding: 8px;">
          <div ref="timelineRef" style="width: 100%; height: 240px;"></div>
        </div>
      </div>

      <!-- Severity Donut -->
      <div class="card">
        <div class="card-header">
          <h2 class="text-sm font-semibold">Severity Distribution</h2>
        </div>
        <div class="card-body" style="padding: 8px;">
          <div ref="severityRef" style="width: 100%; height: 240px;"></div>
        </div>
      </div>
    </div>

    <!-- Attack Types + Top Attackers -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="card">
        <div class="card-header">
          <h2 class="text-sm font-semibold">Top Attack Types</h2>
        </div>
        <div class="card-body" style="padding: 8px;">
          <div ref="attackTypesRef" style="width: 100%; height: 220px;"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-header">
          <h2 class="text-sm font-semibold">Top Attacker IPs</h2>
        </div>
        <div class="card-body" style="padding: 8px;">
          <div ref="topAttackersRef" style="width: 100%; height: 220px;"></div>
        </div>
      </div>
    </div>

    <!-- Live Feed -->
    <div class="card">
      <div class="card-header">
        <h2 class="text-sm font-semibold">Live Security Feed</h2>
        <span class="live-dot">Live</span>
      </div>
      <div class="card-body max-h-80 overflow-y-auto">
        <div v-if="state.liveFeed.length === 0" class="text-center py-8 text-cyber-textmuted text-sm">
          Waiting for security events…
        </div>
        <div v-else class="space-y-1">
          <div
            v-for="(evt, i) in state.liveFeed.slice(0, 30)"
            :key="evt.id || i"
            class="flex items-center gap-3 px-2 py-1.5 rounded text-xs hover:bg-cyber-border/20 transition-colors"
            :class="{ 'flash-row': i === 0 }"
          >
            <span class="severity-dot" :class="(evt.severity || 'info').toLowerCase()" />
            <span class="text-cyber-textmuted font-mono">{{ formatTime(evt.timestamp) }}</span>
            <span class="badge" :class="getSeverityClass(evt.severity)">{{ evt.severity }}</span>
            <span class="text-cyber-text font-medium truncate flex-1">{{ evt.rule_name }}</span>
            <span class="text-cyber-textdim font-mono whitespace-nowrap">{{ evt.source_ip }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- CVE References -->
    <div v-if="cveRefs.length > 0" class="card">
      <div class="card-header">
        <h2 class="text-sm font-semibold">CVE References in Attacks</h2>
      </div>
      <div class="card-body">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          <div
            v-for="cve in cveRefs"
            :key="cve.cve_id"
            class="flex items-center gap-2 px-3 py-2 rounded bg-cyber-bg border border-cyber-border"
          >
            <span class="badge" :class="getSeverityClass(cve.cvss_severity)">{{ cve.cvss_severity }}</span>
            <span class="font-mono text-xs text-cyber-accent">{{ cve.cve_id }}</span>
            <span class="text-xs text-cyber-textdim truncate flex-1">{{ cve.title }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
