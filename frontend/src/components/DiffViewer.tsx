import { useMemo } from 'react'

interface Props {
  diff: string
}

export default function DiffViewer({ diff }: Props) {
  const lines = useMemo(() => diff.split('\n'), [diff])

  return (
    <div className="rounded-xl border border-slate-200 overflow-hidden">
      <div className="px-4 py-2 bg-slate-50 text-slate-500 text-xs font-sans border-b border-slate-200">
        Unified Diff
      </div>
      <pre className="overflow-x-auto text-[13px] leading-6 m-0">
        <code>
          {lines.map((line, i) => {
            let bg = ''
            let textColor = 'text-slate-700'
            if (line.startsWith('@@')) {
              bg = 'bg-cyan-50'
              textColor = 'text-cyan-700'
            } else if (line.startsWith('+')) {
              bg = 'bg-emerald-50'
              textColor = 'text-emerald-700'
            } else if (line.startsWith('-')) {
              bg = 'bg-red-50'
              textColor = 'text-red-600'
            }
            return (
              <div key={i} className={`flex ${bg}`}>
                <span className="w-10 flex-shrink-0 text-right pr-3 text-slate-400 select-none">
                  {i + 1}
                </span>
                <span className={`flex-1 ${textColor}`}>{line}</span>
              </div>
            )
          })}
        </code>
      </pre>
    </div>
  )
}
