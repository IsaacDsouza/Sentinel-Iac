import { useState } from 'react'
import { useStore } from '../store'

export default function Navbar() {
  const { currentPage, navigate } = useStore()
  const [apiKey, setApiKey] = useState(localStorage.getItem('apiKey') ?? '')

  const handleApiKeyBlur = () => {
    if (apiKey) {
      localStorage.setItem('apiKey', apiKey)
    } else {
      localStorage.removeItem('apiKey')
    }
  }

  const isActive = (page: string) => {
    if (page === 'scans') return currentPage === 'scans' || currentPage === 'scan-detail'
    return currentPage === page
  }

  return (
    <nav className="bg-slate-900 border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
        <div className="flex items-center gap-8">
          <button onClick={() => navigate('dashboard')} className="flex items-center gap-2.5">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6 text-indigo-400">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
            <span className="text-white font-semibold text-base tracking-tight">Sentinel IaC</span>
          </button>
          <div className="flex items-center gap-1">
            <button
              onClick={() => navigate('dashboard')}
              className={`relative px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                isActive('dashboard')
                  ? 'text-white bg-slate-800'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => navigate('scans')}
              className={`relative px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                isActive('scans')
                  ? 'text-white bg-slate-800'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              Scans
            </button>
          </div>
        </div>
        <input
          type="password"
          placeholder="API Key"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          onBlur={handleApiKeyBlur}
          className="px-3 py-1.5 text-xs rounded-md bg-slate-800 border border-slate-700 text-slate-300 placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-36"
        />
      </div>
    </nav>
  )
}
