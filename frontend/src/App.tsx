import { useState } from 'react'

function App() {
  const [count, setCount] = useState(0)

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex items-center justify-center">
      <div className="text-center">
        <div className="mb-8">
          <h1 className="text-5xl font-bold text-green-500 mb-4">
            ⚡ Project Optimus
          </h1>
          <p className="text-xl text-gray-400">
            AI-Driven Autonomous Penetration Testing Agent
          </p>
        </div>
        
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-8 max-w-md mx-auto">
          <h2 className="text-2xl font-semibold mb-4 text-green-400">Setup Test</h2>
          
          <div className="space-y-4 text-left">
            <div className="flex items-center gap-2">
              <span className="text-green-500">✓</span>
              <span>React 18 + TypeScript</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-green-500">✓</span>
              <span>TailwindCSS Configured</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-green-500">✓</span>
              <span>Vite Build Tool</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-green-500">✓</span>
              <span>Dark Theme Active</span>
            </div>
          </div>

          <div className="mt-6">
            <button
              onClick={() => setCount((count) => count + 1)}
              className="bg-green-500 hover:bg-green-600 text-white font-semibold px-6 py-3 rounded-lg transition-colors"
            >
              Counter: {count}
            </button>
          </div>

          <div className="mt-6 text-sm text-gray-500">
            Click the button to test React state management
          </div>
        </div>

        <div className="mt-8 text-gray-600">
          <p>Backend: Flask + TensorFlow + scikit-learn</p>
          <p>Frontend: React + TypeScript + TailwindCSS</p>
        </div>
      </div>
    </div>
  )
}

export default App
