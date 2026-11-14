// CyberWatch IDS — TypeScript type definitions

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low'
export type ActionType = 'block' | 'alert' | 'log'

export interface SecurityEvent {
  id: number
  timestamp: string
  event_type: string
  attack_type: string | null
  severity: Severity
  source_ip: string
  source_port: number | null
  destination: string
  method: string
  path: string
  payload: string
  user_agent: string | null
  rule_id: string
  rule_name: string
  rule_description: string
  matched_pattern: string
  matched_cve: string | null
  action: ActionType
  blocked: number // 0 or 1
}

export interface CVEEntry {
  cve_id: string
  title: string
  description: string
  cvss_score: number
  cvss_severity: Severity
  cvss_vector: string
  cwe_id: string
  affected_product: string
  affected_versions: string
  patched_version: string
  attack_vector: string
  impact: string
  remediation: string
  references: string
  published_date: string
  last_modified: string
  is_web_vuln: number
  tags: string
}

export interface IDSRule {
  rule_id: string
  rule_name: string
  rule_description: string
  attack_type: string
  severity: Severity
  pattern: string
  pattern_flags: string
  action: ActionType
  related_cve: string | null
  enabled: number
}

export interface Alert {
  id: number
  event_id: number | null
  alert_time: string
  alert_type: string
  message: string
  acknowledged: number
  acknowledged_by: string | null
  acknowledged_at: string | null
}

export interface IPReputation {
  ip_address: string
  reputation_score: number
  threat_level: ThreatLevel
  first_seen: string
  last_seen: string
  total_events: number
  blocked: number
}

export interface TopAttackType {
  event_type: string
  attack_type: string
  count: number
}

export interface TopAttacker {
  source_ip: string
  count: number
  max_severity: Severity
}

export interface RecentEventBucket {
  hour: string
  count: number
}

export interface CVEMatch {
  matched_cve: string
  count: number
}

export interface Stats {
  totalEvents: number
  blockedEvents: number
  criticalEvents: number
  highEvents: number
  uniqueAttackers: number
  activeAlerts: number
  topAttackTypes: TopAttackType[]
  topAttackers: TopAttacker[]
  recentEvents: RecentEventBucket[]
  cveMatches: CVEMatch[]
}

export interface WSMessage {
  type: 'events' | 'alerts' | 'stats'
  data: any
}

export interface SimulatorStatus {
  running: boolean
}
