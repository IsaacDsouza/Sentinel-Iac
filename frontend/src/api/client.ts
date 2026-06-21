const API_BASE = ''

function getApiKey(): string | null {
  return localStorage.getItem('apiKey')
}

export interface Scan {
  id: string
  target_path: string
  created_at: string
  summary: string
}

export interface ScanDetail extends Scan {
  findings: Finding[]
}

export interface Finding {
  id: string
  scan_id?: string
  rule_id: string
  title: string
  severity: string
  file_path?: string
  line: number
  explanation?: string
  priority_score?: number
  patch_diff?: string
  validated?: boolean
  engine?: string
}

export interface Stats {
  total_scans: number
  total_findings: number
  findings_over_time: Record<string, number>
  severity_counts: Record<string, number>
}

export async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}/api${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(getApiKey() ? { 'X-API-Key': getApiKey()! } : {}),
    },
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`GET ${path} failed (${res.status}): ${text}`)
  }
  return res.json()
}

export async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}/api${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(getApiKey() ? { 'X-API-Key': getApiKey()! } : {}),
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`POST ${path} failed (${res.status}): ${text}`)
  }
  return res.json()
}

export function getScanEvents(scanId: string): EventSource {
  const url = `${API_BASE}/api/scans/${scanId}/events`
  return new EventSource(url)
}
