import { useEffect } from 'react'
import { useStore } from '../store'
import TrendsChart from '../components/TrendsChart'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  note: '#94a3b8',
}

const cards = [
  {
    key: 'total_scans',
    label: 'Total Scans',
    color: 'from-indigo-500 to-blue-500',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
      </svg>
    ),
  },
  {
    key: 'total_findings',
    label: 'Total Findings',
    color: 'from-violet-500 to-purple-500',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
        <circle cx="11" cy="11" r="8" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
      </svg>
    ),
  },
  {
    key: 'critical',
    label: 'Critical',
    color: 'from-red-500 to-rose-500',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
        <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
        <line x1="12" y1="9" x2="12" y2="13" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
      </svg>
    ),
  },
  {
    key: 'high',
    label: 'High',
    color: 'from-orange-500 to-amber-500',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-5 h-5">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
  },
]

function StatCardSkeleton() {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 animate-pulse">
      <div className="flex items-center gap-4">
        <div className="w-10 h-10 bg-slate-200 rounded-lg" />
        <div className="flex-1 space-y-2">
          <div className="h-4 bg-slate-200 rounded w-20" />
          <div className="h-7 bg-slate-200 rounded w-12" />
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { stats, loading, error, fetchStats } = useStore()

  useEffect(() => {
    fetchStats()
  }, [fetchStats])

  if (loading && !stats) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>
          <p className="text-slate-500 text-sm mt-1">Overview of all infrastructure scans</p>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-50 border border-red-200 rounded-xl p-5 text-red-700 text-sm flex items-center justify-between">
        <span>{error}</span>
        <button
          onClick={fetchStats}
          className="px-3 py-1.5 bg-red-100 hover:bg-red-200 rounded-lg text-sm font-medium transition-colors"
        >
          Retry
        </button>
      </div>
    )
  }

  if (!stats) {
    return (
      <div className="text-center py-20">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-12 h-12 text-slate-300 mx-auto mb-4">
          <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
          <polyline points="14 2 14 8 20 8" />
        </svg>
        <p className="text-slate-400 text-sm">No scan data available yet.</p>
        <p className="text-slate-400 text-sm mt-1">Run your first scan to see statistics.</p>
      </div>
    )
  }

  const severityBreakdown = Object.entries(stats.severity_counts ?? {}).map(([severity, count]) => ({ severity, count }))
  const findingsOverTime = Object.entries(stats.findings_over_time ?? {}).map(([date, count]) => ({ date, count }))

  const statValues: Record<string, number> = {
    total_scans: stats.total_scans,
    total_findings: stats.total_findings,
    critical: stats.severity_counts?.critical ?? 0,
    high: stats.severity_counts?.high ?? 0,
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>
        <p className="text-slate-500 text-sm mt-1">Overview of all infrastructure scans</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        {cards.map((card) => (
          <div key={card.key} className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm relative overflow-hidden">
            <div className={`absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b ${card.color}`} />
            <div className="flex items-center gap-4">
              <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${card.color} flex items-center justify-center text-white`}>
                {card.icon}
              </div>
              <div>
                <div className="text-slate-500 text-xs font-medium uppercase tracking-wider">{card.label}</div>
                <div className="text-2xl font-bold text-slate-900 mt-0.5">{statValues[card.key]}</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-700 mb-4">Findings Over Time</h3>
          {findingsOverTime.length > 0 ? (
            <TrendsChart data={findingsOverTime} />
          ) : (
            <div className="flex items-center justify-center h-[300px] text-slate-400 text-sm">No data yet</div>
          )}
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-700 mb-4">Severity Distribution</h3>
          {severityBreakdown.length > 0 ? (
            <div className="flex items-center justify-center h-[300px]">
              <ResponsiveContainer width="60%" height="100%">
                <PieChart>
                  <Pie
                    data={severityBreakdown}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%"
                    cy="50%"
                    outerRadius={90}
                    innerRadius={50}
                    paddingAngle={3}
                  >
                    {severityBreakdown.map((s) => (
                      <Cell key={s.severity} fill={severityColors[s.severity] ?? '#94a3b8'} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: '#fff',
                      border: '1px solid #e2e8f0',
                      borderRadius: '8px',
                      fontSize: '13px',
                      boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2.5">
                {severityBreakdown.map((s) => (
                  <div key={s.severity} className="flex items-center gap-2.5">
                    <div className="w-3 h-3 rounded-sm" style={{ background: severityColors[s.severity] ?? '#94a3b8' }} />
                    <span className="text-sm text-slate-600 capitalize min-w-[60px]">{s.severity}</span>
                    <span className="text-sm font-semibold text-slate-900">{s.count}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-slate-400 text-sm">No data yet</div>
          )}
        </div>
      </div>
    </div>
  )
}
