import { useEffect, useState } from 'react'
import { useStore } from '../store'
import SeverityBadge from './SeverityBadge'
import DiffViewer from './DiffViewer'

export default function FindingDrawer() {
  const { selectedFinding, setSelectedFinding } = useStore()
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    if (selectedFinding) {
      requestAnimationFrame(() => setVisible(true))
    } else {
      setVisible(false)
    }
  }, [selectedFinding])

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSelectedFinding(null)
    }
    document.addEventListener('keydown', handleKey)
    return () => document.removeEventListener('keydown', handleKey)
  }, [setSelectedFinding])

  if (!selectedFinding) return null

  return (
    <>
      <div
        className={`fixed inset-0 bg-black/50 z-40 transition-opacity duration-200 ${visible ? 'opacity-100' : 'opacity-0'}`}
        onClick={() => setSelectedFinding(null)}
      />
      <div
        className={`fixed top-0 right-0 h-full w-[650px] max-w-full bg-white shadow-2xl z-50 overflow-y-auto drawer-scroll transition-transform duration-300 ease-out ${visible ? 'translate-x-0' : 'translate-x-full'}`}
      >
        <div className="sticky top-0 bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between z-10">
          <h2 className="text-lg font-semibold text-slate-900">Finding Detail</h2>
          <button
            onClick={() => setSelectedFinding(null)}
            className="text-slate-400 hover:text-slate-600 p-1 rounded-md hover:bg-slate-100 transition-colors"
          >
            <svg viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5">
              <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div>
            <div className="flex items-center gap-3 mb-3">
              <SeverityBadge severity={selectedFinding.severity} />
              <span className="text-xs text-slate-500 font-mono bg-slate-100 px-2 py-0.5 rounded">
                {selectedFinding.rule_id}
              </span>
            </div>
            <h3 className="text-xl font-semibold text-slate-900">{selectedFinding.title}</h3>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="bg-slate-50 rounded-lg p-3.5">
              <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">File</div>
              <div className="text-slate-900 font-mono text-sm truncate">{selectedFinding.file_path ?? '-'}</div>
            </div>
            <div className="bg-slate-50 rounded-lg p-3.5">
              <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Line</div>
              <div className="text-slate-900 font-mono text-sm">{selectedFinding.line}</div>
            </div>
            <div className="bg-slate-50 rounded-lg p-3.5">
              <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Engine</div>
              <div className="text-slate-900 font-mono text-sm">{selectedFinding.engine ?? '-'}</div>
            </div>
            <div className="bg-slate-50 rounded-lg p-3.5">
              <div className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-1">Priority</div>
              <div className="text-slate-900 font-semibold text-sm">{selectedFinding.priority_score ?? '-'}</div>
            </div>
          </div>

          {selectedFinding.explanation && (
            <div>
              <h4 className="text-sm font-semibold text-slate-700 mb-2">Explanation</h4>
              <p className="text-sm text-slate-600 leading-relaxed bg-slate-50 rounded-lg p-4">
                {selectedFinding.explanation}
              </p>
            </div>
          )}

          {selectedFinding.patch_diff && (
            <div>
              <h4 className="text-sm font-semibold text-slate-700 mb-2">Patch / Remediation</h4>
              <DiffViewer diff={selectedFinding.patch_diff} />
            </div>
          )}
        </div>

        <div className="sticky bottom-0 bg-white border-t border-slate-200 px-6 py-4">
          <button
            onClick={() => setSelectedFinding(null)}
            className="w-full px-4 py-2 text-sm font-medium text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </>
  )
}
