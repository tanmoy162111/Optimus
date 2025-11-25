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
    <nav className="bg-gray-900 border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-green-500" />
            <span className="text-xl font-bold text-green-500">Project Optimus</span>
          </div>
          
          <div className="flex gap-2">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-green-500 text-white'
                      : 'text-gray-400 hover:bg-gray-800 hover:text-white'
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
      <div className="min-h-screen bg-black text-white">
        <Navigation />
        <main className="max-w-7xl mx-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/models" element={<div className="p-6"><h1 className="text-3xl font-bold text-green-500">AI Models</h1><p className="text-gray-400 mt-2">Model management coming soon...</p></div>} />
            <Route path="/metrics" element={<div className="p-6"><h1 className="text-3xl font-bold text-green-500">Metrics</h1><p className="text-gray-400 mt-2">Performance metrics coming soon...</p></div>} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

export default App
