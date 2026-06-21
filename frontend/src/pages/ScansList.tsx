import { useEffect, useState, useMemo } from 'react'
import { useStore } from '../store'
import SeverityBadge from '../components/SeverityBadge'

function parseSummary(summary: string) {
  try { return JSON.parse(summary) } catch { return {} }
}

export default function ScansList() {
  const { scans, loading, error, fetchScans, triggerScan, navigate } = useStore()
  const [showModal, setShowModal] = useState(false)
  const [targetPath, setTargetPath] = useState('')
  const [creating, setCreating] = useState(false)
  const [search, setSearch] = useState('')

  useEffect(() => {
    fetchScans()
  }, [fetchScans])

  const handleCreate = async () => {
    if (!targetPath.trim()) return
    setCreating(true)
    await triggerScan(targetPath.trim())
    setCreating(false)
    setShowModal(false)
    setTargetPath('')
    fetchScans()
  }

  const filteredScans = useMemo(
    () => scans.filter((s) => s.target_path.toLowerCase().includes(search.toLowerCase())),
    [scans, search]
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Scans</h1>
          <p className="text-slate-500 text-sm mt-1">All infrastructure security scans</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors shadow-sm"
        >
          <svg viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4">
            <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
          </svg>
          New Scan
        </button>
      </div>

      {loading && scans.length === 0 && (
        <div className="space-y-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="bg-white rounded-xl border border-slate-200 p-5 animate-pulse">
              <div className="flex items-center gap-4">
                <div className="h-4 bg-slate-200 rounded w-16" />
                <div className="h-4 bg-slate-200 rounded w-48" />
                <div className="h-4 bg-slate-200 rounded w-12 ml-auto" />
              </div>
            </div>
          ))}
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-5 text-red-700 text-sm flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchScans}
            className="px-3 py-1.5 bg-red-100 hover:bg-red-200 rounded-lg text-sm font-medium transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {!loading && scans.length === 0 && !error && (
        <div className="bg-white rounded-xl border border-slate-200 p-12 text-center shadow-sm">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-12 h-12 text-slate-300 mx-auto mb-4">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
            <polyline points="14 2 14 8 20 8" />
          </svg>
          <p className="text-slate-400 text-sm">No scans yet</p>
          <button
            onClick={() => setShowModal(true)}
            className="mt-4 px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors"
          >
            Create your first scan
          </button>
        </div>
      )}

      {scans.length > 0 && (
        <>
          <div className="relative">
            <svg viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2">
              <path fillRule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clipRule="evenodd" />
            </svg>
            <input
              type="text"
              placeholder="Search scans by target path..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 border border-slate-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 bg-white"
            />
          </div>

          {filteredScans.length === 0 ? (
            <div className="bg-white rounded-xl border border-slate-200 p-8 text-center shadow-sm">
              <p className="text-slate-400 text-sm">No scans match your search.</p>
            </div>
          ) : (
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    <th className="text-left px-5 py-3.5 font-semibold text-slate-500 text-xs uppercase tracking-wider">Status</th>
                    <th className="text-left px-5 py-3.5 font-semibold text-slate-500 text-xs uppercase tracking-wider">Target Path</th>
                    <th className="text-center px-5 py-3.5 font-semibold text-slate-500 text-xs uppercase tracking-wider">Findings</th>
                    <th className="text-left px-5 py-3.5 font-semibold text-slate-500 text-xs uppercase tracking-wider">Severity</th>
                    <th className="text-left px-5 py-3.5 font-semibold text-slate-500 text-xs uppercase tracking-wider">Date</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredScans.map((scan) => {
                    const s = parseSummary(scan.summary)
                    const totalFindings = s.total ?? 0
                    const sevCounts: [string, number][] = Object.entries(s.severity_counts ?? {})
                    return (
                      <tr
                        key={scan.id}
                        onClick={() => navigate('scan-detail', scan.id)}
                        className="hover:bg-slate-50 cursor-pointer transition-colors"
                      >
                        <td className="px-5 py-4">
                          <span className="inline-flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-emerald-500" />
                            <span className="text-xs text-emerald-700 font-medium">Completed</span>
                          </span>
                        </td>
                        <td className="px-5 py-4 font-mono text-sm text-slate-900 max-w-[300px] truncate">
                          {scan.target_path}
                        </td>
                        <td className="px-5 py-4 text-center font-semibold text-slate-900">
                          {totalFindings}
                        </td>
                        <td className="px-5 py-4">
                          <div className="flex flex-wrap gap-1.5">
                            {sevCounts.map(([sev, count]) => (
                              <div key={sev} className="flex items-center gap-1">
                                <SeverityBadge severity={sev} />
                                <span className="text-xs text-slate-400">({count})</span>
                              </div>
                            ))}
                            {sevCounts.length === 0 && (
                              <span className="text-xs text-slate-400">-</span>
                            )}
                          </div>
                        </td>
                        <td className="px-5 py-4 text-slate-500 text-sm whitespace-nowrap">
                          {new Date(scan.created_at).toLocaleDateString('en-US', {
                            month: 'short',
                            day: 'numeric',
                            year: 'numeric',
                          })}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {showModal && (
        <>
          <div className="fixed inset-0 bg-black/50 z-40" onClick={() => setShowModal(false)} />
          <div className="fixed inset-0 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl shadow-2xl p-6 w-full max-w-md mx-4">
              <h2 className="text-lg font-semibold text-slate-900 mb-1">New Scan</h2>
              <p className="text-sm text-slate-500 mb-5">Scan an infrastructure directory for security issues.</p>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Target Path</label>
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="e.g. /path/to/terraform or repo:owner/name"
                className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                onKeyDown={(e) => e.key === 'Enter' && handleCreate()}
              />
              <div className="flex justify-end gap-3 mt-6">
                <button
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-sm font-medium text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreate}
                  disabled={creating || !targetPath.trim()}
                  className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shadow-sm"
                >
                  {creating ? 'Starting...' : 'Start Scan'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
