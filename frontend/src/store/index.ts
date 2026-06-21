import { create } from 'zustand'
import type { Scan, ScanDetail, Finding, Stats } from '../api/client'
import { get, post } from '../api/client'

interface AppState {
  scans: Scan[]
  selectedScan: ScanDetail | null
  selectedFinding: Finding | null
  stats: Stats | null
  loading: boolean
  error: string | null
  currentPage: string
  scanIdParam: string | null
  fetchScans: () => Promise<void>
  fetchScan: (id: string) => Promise<void>
  fetchStats: () => Promise<void>
  triggerScan: (path: string) => Promise<void>
  setSelectedFinding: (finding: Finding | null) => void
  navigate: (page: string, scanId?: string) => void
}

export const useStore = create<AppState>((set) => ({
  scans: [],
  selectedScan: null,
  selectedFinding: null,
  stats: null,
  loading: false,
  error: null,
  currentPage: 'dashboard',
  scanIdParam: null,

  fetchScans: async () => {
    set({ loading: true, error: null })
    try {
      const data = await get<{ scans: Scan[] }>('/scans')
      set({ scans: data.scans, loading: false })
    } catch (e) {
      set({ error: (e as Error).message, loading: false })
    }
  },

  fetchScan: async (id: string) => {
    set({ loading: true, error: null })
    try {
      const scan = await get<ScanDetail>(`/scans/${id}`)
      set({ selectedScan: scan, loading: false })
    } catch (e) {
      set({ error: (e as Error).message, loading: false })
    }
  },

  fetchStats: async () => {
    set({ loading: true, error: null })
    try {
      const stats = await get<Stats>('/stats')
      set({ stats, loading: false })
    } catch (e) {
      set({ error: (e as Error).message, loading: false })
    }
  },

  triggerScan: async (path: string) => {
    set({ loading: true, error: null })
    try {
      const result = await post<{ scan_id: string }>('/scans', { target_path: path, enrich: false })
      set({ loading: false, currentPage: 'scan-detail', scanIdParam: result.scan_id, selectedScan: null })
    } catch (e) {
      set({ error: (e as Error).message, loading: false })
    }
  },

  setSelectedFinding: (finding) => set({ selectedFinding: finding }),

  navigate: (page, scanId) =>
    set({ currentPage: page, scanIdParam: scanId ?? null }),
}))
