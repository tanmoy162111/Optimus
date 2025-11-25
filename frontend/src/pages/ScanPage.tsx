import { useState } from 'react';
import { api } from '../services/api';
import { useScanStore } from '../store/scanStore';
import { Play, Square, Loader2 } from 'lucide-react';

export default function ScanPage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const { currentScan, isScanning, setCurrentScan, setIsScanning } = useScanStore();

  const handleStartScan = async () => {
    if (!target.trim()) {
      alert('Please enter a target URL');
      return;
    }

    setLoading(true);
    try {
      const response = await api.scan.start(target);
      setCurrentScan(response.data as any);
      setIsScanning(true);
      console.log('Scan started:', response.data);
    } catch (error: any) {
      console.error('Error starting scan:', error);
      alert(error.response?.data?.error || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  const handleStopScan = async () => {
    if (!currentScan) return;

    try {
      await api.scan.stop(currentScan.scan_id);
      setIsScanning(false);
      console.log('Scan stopped');
    } catch (error) {
      console.error('Error stopping scan:', error);
    }
  };

  return (
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-green-500 mb-2">
          Start New Scan
        </h1>
        <p className="text-gray-400">
          Configure and launch an autonomous penetration test
        </p>
      </div>

      {/* Scan Configuration */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
        <h2 className="text-xl font-semibold mb-4 text-green-400">
          Target Configuration
        </h2>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target URL
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg 
                       text-gray-100 placeholder-gray-500 focus:outline-none 
                       focus:ring-2 focus:ring-green-500 focus:border-transparent"
              disabled={isScanning}
            />
          </div>

          <div className="flex gap-4">
            <button
              onClick={handleStartScan}
              disabled={loading || isScanning}
              className="flex items-center gap-2 px-6 py-3 bg-green-500 hover:bg-green-600 
                       text-white font-semibold rounded-lg transition-colors
                       disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Starting...
                </>
              ) : (
                <>
                  <Play className="w-5 h-5" />
                  Start Scan
                </>
              )}
            </button>

            {isScanning && (
              <button
                onClick={handleStopScan}
                className="flex items-center gap-2 px-6 py-3 bg-red-500 hover:bg-red-600 
                         text-white font-semibold rounded-lg transition-colors"
              >
                <Square className="w-5 h-5" />
                Stop Scan
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Current Scan Status */}
      {currentScan && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-xl font-semibold mb-4 text-green-400">
            Current Scan
          </h2>
          
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-400">Scan ID:</span>
              <span className="text-gray-200 font-mono">{currentScan.scan_id}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Target:</span>
              <span className="text-gray-200">{currentScan.target}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Phase:</span>
              <span className="text-blue-400 font-semibold capitalize">
                {currentScan.phase}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Status:</span>
              <span className={`font-semibold ${
                currentScan.status === 'running' ? 'text-green-500' : 'text-yellow-500'
              }`}>
                {currentScan.status}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Findings:</span>
              <span className="text-gray-200">{currentScan.findings?.length || 0}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-400">Coverage:</span>
              <span className="text-gray-200">
                {((currentScan.coverage || 0) * 100).toFixed(1)}%
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
