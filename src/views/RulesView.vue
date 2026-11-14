<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import type { IDSRule } from '@/api/types'

const rules = ref<IDSRule[]>([])
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    rules.value = await api.getRules()
  } catch (e) {
    console.error(e)
  }
  loading.value = false
}

async function toggle(rule: IDSRule) {
  try {
    await api.toggleRule(rule.rule_id)
    rule.enabled = rule.enabled ? 0 : 1
  } catch (e) {
    console.error(e)
  }
}

function getSeverityClass(sev: string) {
  return `badge-${(sev || 'info').toLowerCase()}`
}

onMounted(load)
</script>

<template>
  <div class="space-y-4 animate-fade-in">
    <div class="card">
      <div class="card-header">
        <h2 class="text-sm font-semibold">IDS Detection Rules</h2>
        <div class="flex items-center gap-2">
          <span class="text-[11px] text-cyber-textmuted">{{ rules.length }} total</span>
          <span class="text-[11px] text-cyber-low">{{ rules.filter(r => r.enabled).length }} active</span>
          <button class="btn btn-primary text-xs" @click="load">Refresh</button>
        </div>
      </div>
      <div class="card-body">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div
            v-for="rule in rules"
            :key="rule.rule_id"
            class="card p-3"
            :class="{ 'opacity-50': !rule.enabled }"
          >
            <div class="flex items-start justify-between mb-2">
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 mb-1">
                  <span class="font-mono text-xs text-cyber-accent">{{ rule.rule_id }}</span>
                  <span class="badge" :class="getSeverityClass(rule.severity)">{{ rule.severity }}</span>
                  <span v-if="rule.action === 'block'" class="badge badge-critical">Block</span>
                  <span v-else-if="rule.action === 'alert'" class="badge badge-high">Alert</span>
                  <span v-else class="badge badge-info">Log</span>
                </div>
                <div class="text-sm font-medium text-cyber-text">{{ rule.rule_name }}</div>
                <div class="text-xs text-cyber-textmuted mt-1">{{ rule.rule_description }}</div>
              </div>
            </div>
            <div class="flex items-center justify-between gap-2 mt-2 pt-2 border-t border-cyber-border/50">
              <code class="text-[10px] text-cyber-accent bg-cyber-bg px-2 py-1 rounded font-mono flex-1 truncate" :title="rule.pattern">{{ rule.pattern }}</code>
              <div
                class="toggle"
                :class="rule.enabled ? 'on' : 'off'"
                @click="toggle(rule)"
                role="switch"
                :aria-checked="!!rule.enabled"
                tabindex="0"
                @keydown.enter.prevent="toggle(rule)"
              >
                <span class="toggle-knob" />
              </div>
            </div>
            <div v-if="rule.related_cve" class="mt-1.5">
              <span class="font-mono text-[10px] text-cyber-textdim">CVE: {{ rule.related_cve }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
