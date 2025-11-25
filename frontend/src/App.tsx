import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import { Shield, Home, Activity, Brain, BarChart3 } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'

function Navigation() {
  const location = useLocation()
  
  const navItems = [
    { path: '/', icon: Home, label: 'Dashboard' },
    { path: '/scan', icon: Activity, label: 'New Scan' },
    { path: '/models', icon: Brain, label: 'AI Models' },
    { path: '/metrics', icon: BarChart3, label: 'Metrics' },
  ]

  return (
    <nav className="bg-gray-900 border-b border-cyan-500/30 backdrop-blur-sm">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-cyan-400 animate-pulse" />
            <span className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">Optimus</span>
          </div>
          
          <div className="flex gap-2">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg shadow-cyan-500/50'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-cyan-400 border border-transparent hover:border-cyan-500/30'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  {item.label}
                </Link>
              )
            })}
          </div>
        </div>
      </div>
    </nav>
  )
}

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-slate-900 to-black text-white">
        <Navigation />
        <main className="max-w-7xl mx-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/models" element={<div className="p-6"><h1 className="text-3xl font-bold text-cyan-400">AI Models</h1><p className="text-gray-400 mt-2">Model management coming soon...</p></div>} />
            <Route path="/metrics" element={<div className="p-6"><h1 className="text-3xl font-bold text-cyan-400">Metrics</h1><p className="text-gray-400 mt-2">Performance metrics coming soon...</p></div>} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

export default App
