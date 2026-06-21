interface Props {
  severity: string
}

const colors: Record<string, string> = {
  critical: 'bg-red-50 text-red-700 ring-1 ring-red-600/20',
  high: 'bg-orange-50 text-orange-700 ring-1 ring-orange-600/20',
  medium: 'bg-amber-50 text-amber-700 ring-1 ring-amber-600/20',
  low: 'bg-emerald-50 text-emerald-700 ring-1 ring-emerald-600/20',
  note: 'bg-slate-50 text-slate-700 ring-1 ring-slate-600/20',
}

export default function SeverityBadge({ severity }: Props) {
  const cls = colors[severity.toLowerCase()] ?? colors.note
  const label = severity.charAt(0).toUpperCase() + severity.slice(1)
  return (
    <span className={`inline-block px-2 py-0.5 rounded-md text-xs font-medium ${cls}`}>
      {label}
    </span>
  )
}
