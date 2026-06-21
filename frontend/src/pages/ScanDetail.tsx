import { useEffect, useState, useMemo } from 'react'
import { useStore } from '../store'
import SeverityBadge from '../components/SeverityBadge'
import FindingDrawer from '../components/FindingDrawer'
import { getScanEvents } from '../api/client'
import type { Finding } from '../api/client'

function parseSummary(summary: string) {
  try { return JSON.parse(summary) } catch { return {} }
}

export default function ScanDetail() {
  const { scanIdParam, selectedScan, loading, error, fetchScan, setSelectedFinding, navigate } =
    useStore()
  const [findings, setFindings] = useState<Finding[]>([])
  const [search, setSearch] = useState('')

  useEffect(() => {
    if (scanIdParam) {
      fetchScan(scanIdParam)
    }
  }, [scanIdParam, fetchScan])

  useEffect(() => {
    if (selectedScan?.findings) {
      setFindings(selectedScan.findings)
    }
  }, [selectedScan?.findings])

  useEffect(() => {
    if (!scanIdParam) return
    const es = getScanEvents(scanIdParam)
    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.type === 'completed' || data.type === 'failed') {
          fetchScan(scanIdParam)
        }
        if (data.finding) {
          setFindings((prev) => [...prev, data.finding].filter(
            (f: Finding, i: number, arr: Finding[]) => arr.findIndex((x) => x.id === f.id) === i
          ))
        }
      } catch { /* ignore parse errors */ }
    }
    es.onerror = () => es.close()
    return () => es.close()
  }, [scanIdParam, fetchScan])

  const filteredFindings = useMemo(
    () => findings.filter(
      (f) =>
        f.title.toLowerCase().includes(search.toLowerCase()) ||
        f.rule_id.toLowerCase().includes(search.toLowerCase()) ||
        (f.file_path ?? '').toLowerCase().includes(search.toLowerCase())
    ),
    [findings, search]
  )

  if (loading && !selectedScan) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <div className="h-8 w-24 bg-slate-200 rounded animate-pulse" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="bg-white rounded-xl border border-slate-200 p-4 animate-pulse">
              <div className="h-3 bg-slate-200 rounded w-16 mb-2" />
              <div className="h-5 bg-slate-200 rounded w-24" />
            </div>
          ))}
        </div>
        <div className="bg-white rounded-xl border border-slate-200 p-4 animate-pulse">
          <div className="h-4 bg-slate-200 rounded w-32 mb-4" />
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-12 bg-slate-100 rounded mb-2" />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-5 text-red-700 text-sm flex items-center justify-between">
        <span>{error}</span>
        <button
          onClick={() => navigate('scans')}
          className="px-3 py-1.5 bg-red-100 hover:bg-red-200 rounded-lg text-sm font-medium transition-colors"
        >
          Back to scans
        </button>
      </div>
    )
  }

  if (!selectedScan) {
    return (
      <div className="text-center py-20">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-12 h-12 text-slate-300 mx-auto mb-4">
          <circle cx="12" cy="12" r="10" />
          <line x1="15" y1="9" x2="9" y2="15" />
          <line x1="9" y1="9" x2="15" y2="15" />
        </svg>
        <p className="text-slate-400 text-sm">Scan not found.</p>
        <button
          onClick={() => navigate('scans')}
          className="mt-4 text-indigo-600 hover:text-indigo-700 text-sm font-medium"
        >
          &larr; Back to scans
        </button>
      </div>
    )
  }

  const parsedSummary = parseSummary(selectedScan.summary)
  const summarySevCounts: [string, number][] = Object.entries(parsedSummary.severity_counts ?? {})
  const uniqueEngines = new Set(findings.map((f) => f.engine).filter(Boolean)).size

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('scans')}
            className="text-slate-400 hover:text-slate-600 p-1.5 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <svg viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5">
              <path fillRule="evenodd" d="M17 10a.75.75 0 01-.75.75H5.612l4.158 3.96a.75.75 0 11-1.04 1.08l-5.5-5.25a.75.75 0 010-1.08l5.5-5.25a.75.75 0 111.04 1.08L5.612 9.25H16.25A.75.75 0 0117 10z" clipRule="evenodd" />
            </svg>
          </button>
          <div>
            <div className="text-xs text-slate-500 font-mono">{selectedScan.id}</div>
            <h1 className="text-xl font-bold text-slate-900">Scan Details</h1>
          </div>
        </div>
        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-sm font-medium bg-emerald-50 text-emerald-700 ring-1 ring-emerald-600/20">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          Completed
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
          <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Target Path</div>
          <div className="text-sm font-mono text-slate-900 truncate">{selectedScan.target_path}</div>
        </div>
        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
          <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Created</div>
          <div className="text-sm text-slate-900">
            {new Date(selectedScan.created_at).toLocaleString()}
          </div>
        </div>
        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
          <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Findings</div>
          <div className="text-2xl font-bold text-slate-900">{findings.length}</div>
        </div>
        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
          <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Engines</div>
          <div className="text-2xl font-bold text-slate-900">{uniqueEngines || 1}</div>
        </div>
      </div>

      {summarySevCounts.length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-700 mb-3">Severity Summary</h3>
          <div className="flex flex-wrap gap-3">
            {summarySevCounts.map(([sev, count]) => (
              <div key={sev} className="flex items-center gap-2">
                <SeverityBadge severity={sev} />
                <span className="text-sm font-semibold text-slate-900">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-700">
            Findings
            <span className="ml-2 text-slate-400 font-normal">{findings.length}</span>
          </h3>
          {findings.length > 0 && (
            <div className="relative">
              <svg viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2">
                <path fillRule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clipRule="evenodd" />
              </svg>
              <input
                type="text"
                placeholder="Filter findings..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8 pr-3 py-1.5 border border-slate-200 rounded-lg text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 w-48"
              />
            </div>
          )}
        </div>
        {filteredFindings.length === 0 ? (
          <div className="p-8 text-center">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-8 h-8 text-slate-300 mx-auto mb-3">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <p className="text-slate-400 text-sm">
              {findings.length === 0 ? 'No findings in this scan.' : 'No findings match your filter.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200">
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wider">Severity</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wider">Rule ID</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wider">Title</th>
                  <th className="text-left px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wider">File</th>
                  <th className="text-center px-5 py-3 font-semibold text-slate-500 text-xs uppercase tracking-wider">Line</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredFindings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="px-5 py-3">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-500">{f.rule_id}</td>
                    <td className="px-5 py-3 text-slate-900 font-medium max-w-[250px] truncate">{f.title}</td>
                    <td className="px-5 py-3 font-mono text-xs text-slate-500 truncate max-w-[200px]">
                      {f.file_path ?? '-'}
                    </td>
                    <td className="px-5 py-3 text-center font-mono text-sm text-slate-700">
                      {f.line}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <FindingDrawer />
    </div>
  )
}
