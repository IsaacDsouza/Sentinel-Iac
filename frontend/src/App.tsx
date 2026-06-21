import { useStore } from './store'
import Navbar from './components/Navbar'
import Dashboard from './pages/Dashboard'
import ScansList from './pages/ScansList'
import ScanDetail from './pages/ScanDetail'

function App() {
  const { currentPage } = useStore()

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />
      case 'scans':
        return <ScansList />
      case 'scan-detail':
        return <ScanDetail />
      default:
        return <Dashboard />
    }
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />
      <main className="max-w-7xl mx-auto px-6 py-8">{renderPage()}</main>
    </div>
  )
}

export default App
