<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api } from '@/api/client'
import type { CVEEntry } from '@/api/types'

const cves = ref<CVEEntry[]>([])
const searchQuery = ref('')
const severityFilter = ref('ALL')
const selectedCVE = ref<CVEEntry | null>(null)
const loading = ref(false)

let searchTimer: ReturnType<typeof setTimeout> | null = null

async function load() {
  loading.value = true
  try {
    cves.value = await api.getCVEs(searchQuery.value, severityFilter.value)
  } catch (e) {
    console.error(e)
  }
  loading.value = false
}

function onSearchInput() {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(load, 250)
}

async function openCVE(id: string) {
  try {
    selectedCVE.value = await api.getCVEById(id)
  } catch (e) {
    console.error(e)
  }
}

function closeModal() {
  selectedCVE.value = null
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
        <h2 class="text-sm font-semibold">CVE Database — Web &amp; Runtime Vulnerability Reference</h2>
        <span class="text-[11px] text-cyber-textmuted">{{ cves.length }} entries</span>
      </div>
      <div class="card-body">
        <!-- Search -->
        <div class="flex flex-wrap gap-2 mb-4">
          <input
            v-model="searchQuery"
            class="input flex-1 min-w-[200px]"
            placeholder="Search CVE ID, title, product, tags…"
            @input="onSearchInput"
          />
          <select v-model="severityFilter" class="input" @change="load">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        <!-- CVE Cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          <div
            v-for="cve in cves"
            :key="cve.cve_id"
            class="card cursor-pointer hover:border-cyber-accent/40 transition-colors p-3"
            @click="openCVE(cve.cve_id)"
          >
            <div class="flex items-center gap-2 mb-2">
              <span class="badge" :class="getSeverityClass(cve.cvss_severity)">{{ cve.cvss_severity }}</span>
              <span class="font-mono text-sm text-cyber-accent font-semibold">{{ cve.cve_id }}</span>
              <span class="text-xs text-cyber-textmuted ml-auto">{{ cve.cvss_score }}</span>
            </div>
            <div class="text-xs text-cyber-text font-medium mb-1 line-clamp-2">{{ cve.title }}</div>
            <div class="text-xs text-cyber-textmuted truncate">{{ cve.affected_product }}</div>
            <div v-if="!cve.is_web_vuln" class="mt-2 inline-flex items-center gap-1 text-[10px] text-cyber-medium">
              <svg viewBox="0 0 24 24" class="w-3 h-3 fill-none stroke-current stroke-width-2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
              Runtime / Infrastructure
            </div>
          </div>
        </div>
        <div v-if="cves.length === 0" class="text-center py-8 text-cyber-textmuted text-sm">
          No CVE entries found
        </div>
      </div>
    </div>

    <!-- CVE Detail Modal -->
    <Teleport to="body">
      <div v-if="selectedCVE" class="modal-backdrop animate-fade-in" @click.self="closeModal" @keydown.escape="closeModal">
        <div class="card max-w-2xl w-full max-h-[85vh] overflow-y-auto animate-slide-up">
          <div class="card-header sticky top-0 bg-cyber-card">
            <div class="flex items-center gap-2">
              <span class="badge" :class="getSeverityClass(selectedCVE.cvss_severity)">{{ selectedCVE.cvss_severity }}</span>
              <span class="font-mono text-lg text-cyber-accent font-bold">{{ selectedCVE.cve_id }}</span>
              <span class="text-sm text-cyber-textmuted">CVSS {{ selectedCVE.cvss_score }}</span>
            </div>
            <button class="btn btn-ghost" @click="closeModal">
              <svg viewBox="0 0 24 24" class="w-5 h-5 fill-none stroke-current stroke-width-2"><path d="M6 6l12 12M6 18L18 6"/></svg>
            </button>
          </div>
          <div class="card-body space-y-4">
            <div>
              <h3 class="text-base font-semibold text-cyber-text">{{ selectedCVE.title }}</h3>
            </div>
            <div class="grid grid-cols-2 gap-3 text-sm">
              <div><span class="text-cyber-textmuted">Product:</span> <span class="text-cyber-text">{{ selectedCVE.affected_product }}</span></div>
              <div><span class="text-cyber-textmuted">Affected:</span> <span class="font-mono text-xs text-cyber-text">{{ selectedCVE.affected_versions }}</span></div>
              <div><span class="text-cyber-textmuted">Patched:</span> <span class="font-mono text-xs text-cyber-low">{{ selectedCVE.patched_version }}</span></div>
              <div><span class="text-cyber-textmuted">CWE:</span> <span class="font-mono text-xs text-cyber-text">{{ selectedCVE.cwe_id }}</span></div>
              <div><span class="text-cyber-textmuted">Vector:</span> <span class="font-mono text-xs text-cyber-text">{{ selectedCVE.attack_vector }}</span></div>
              <div><span class="text-cyber-textmuted">CVSS Vector:</span> <span class="font-mono text-xs text-cyber-textdim">{{ selectedCVE.cvss_vector }}</span></div>
            </div>
            <div>
              <div class="text-xs text-cyber-textmuted uppercase tracking-wide mb-1">Description</div>
              <p class="text-sm text-cyber-text leading-relaxed">{{ selectedCVE.description }}</p>
            </div>
            <div>
              <div class="text-xs text-cyber-textmuted uppercase tracking-wide mb-1">Impact</div>
              <p class="text-sm text-cyber-text leading-relaxed">{{ selectedCVE.impact }}</p>
            </div>
            <div>
              <div class="text-xs text-cyber-textmuted uppercase tracking-wide mb-1">Remediation</div>
              <p class="text-sm text-cyber-low leading-relaxed">{{ selectedCVE.remediation }}</p>
            </div>
            <div>
              <div class="text-xs text-cyber-textmuted uppercase tracking-wide mb-1">Tags</div>
              <div class="flex flex-wrap gap-1">
                <span v-for="tag in selectedCVE.tags?.split(',')" :key="tag" class="badge badge-info">{{ tag.trim() }}</span>
              </div>
            </div>
            <div class="pt-2 border-t border-cyber-border">
              <a v-if="selectedCVE.references" :href="selectedCVE.references" target="_blank" rel="noopener" class="text-xs text-cyber-accent hover:underline">
                View Reference →
              </a>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
