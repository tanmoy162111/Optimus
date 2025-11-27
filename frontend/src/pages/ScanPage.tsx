import { useState } from 'react';
import { api } from '../services/api';
import { useScanStore } from '../store/scanStore';
import { Play, Square, Loader2, FileText, AlertCircle, CheckCircle, Clock } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';
export default function ScanPage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const { currentScan, isScanning, setCurrentScan, setIsScanning, outputLines } = useScanStore();
  const { joinScan } = useWebSocket();

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
      // Join WS room to stream output
      joinScan((response.data as any).scan_id);
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
          {/* Live Output */}
          <div className="mt-6">
            <h3 className="text-lg font-semibold mb-2 text-green-400">Live Output</h3>
            <div className="h-48 overflow-auto bg-black/60 border border-gray-700 rounded p-3 font-mono text-sm text-gray-200">
              {outputLines.length === 0 ? (
                <div className="text-gray-500">No output yet. Waiting for scan to start...</div>
              ) : (
                outputLines.slice(-200).map((line, idx) => (
                  <div key={idx} className="whitespace-pre-wrap">{line}</div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Detailed Report Section */}
      {currentScan && currentScan.status === 'completed' && (
        <div className="mt-6 bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-6">
            <FileText className="w-6 h-6 text-cyan-400" />
            <h2 className="text-2xl font-semibold text-cyan-400">Scan Report</h2>
          </div>

          {/* Summary Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-5 h-5 text-red-400" />
                <span className="text-gray-400 text-sm">Total Findings</span>
              </div>
              <div className="text-3xl font-bold text-gray-100">
                {currentScan.findings?.length || 0}
              </div>
            </div>

            <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="w-5 h-5 text-green-400" />
                <span className="text-gray-400 text-sm">Tools Executed</span>
              </div>
              <div className="text-3xl font-bold text-gray-100">
                {currentScan.tools_executed?.length || 0}
              </div>
            </div>

            <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <Clock className="w-5 h-5 text-blue-400" />
                <span className="text-gray-400 text-sm">Time Elapsed</span>
              </div>
              <div className="text-3xl font-bold text-gray-100">
                {currentScan.time_elapsed || 0}s
              </div>
            </div>

            <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="w-5 h-5 text-cyan-400" />
                <span className="text-gray-400 text-sm">Coverage</span>
              </div>
              <div className="text-3xl font-bold text-gray-100">
                {((currentScan.coverage || 0) * 100).toFixed(0)}%
              </div>
            </div>
          </div>

          {/* Findings by Severity */}
          {currentScan.findings && currentScan.findings.length > 0 && (
            <div className="mb-6">
              <h3 className="text-lg font-semibold mb-3 text-gray-200">Findings by Severity</h3>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <div className="bg-red-900/20 border border-red-800 rounded p-3">
                  <div className="text-red-400 text-sm font-medium mb-1">Critical</div>
                  <div className="text-2xl font-bold text-red-300">
                    {currentScan.findings.filter((f: any) => f.severity >= 9.0).length}
                  </div>
                </div>
                <div className="bg-orange-900/20 border border-orange-800 rounded p-3">
                  <div className="text-orange-400 text-sm font-medium mb-1">High</div>
                  <div className="text-2xl font-bold text-orange-300">
                    {currentScan.findings.filter((f: any) => f.severity >= 7.0 && f.severity < 9.0).length}
                  </div>
                </div>
                <div className="bg-yellow-900/20 border border-yellow-800 rounded p-3">
                  <div className="text-yellow-400 text-sm font-medium mb-1">Medium</div>
                  <div className="text-2xl font-bold text-yellow-300">
                    {currentScan.findings.filter((f: any) => f.severity >= 4.0 && f.severity < 7.0).length}
                  </div>
                </div>
                <div className="bg-blue-900/20 border border-blue-800 rounded p-3">
                  <div className="text-blue-400 text-sm font-medium mb-1">Low</div>
                  <div className="text-2xl font-bold text-blue-300">
                    {currentScan.findings.filter((f: any) => f.severity < 4.0).length}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Tools Used */}
          {currentScan.tools_executed && currentScan.tools_executed.length > 0 && (
            <div className="mb-6">
              <h3 className="text-lg font-semibold mb-3 text-gray-200">Tools Executed</h3>
              <div className="flex flex-wrap gap-2">
                {currentScan.tools_executed.map((tool: string, idx: number) => (
                  <span
                    key={idx}
                    className="px-3 py-1 bg-gray-800 border border-gray-700 rounded-full text-sm text-gray-300"
                  >
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Detailed Findings Table */}
          {currentScan.findings && currentScan.findings.length > 0 && (
            <div>
              <h3 className="text-lg font-semibold mb-3 text-gray-200">Detailed Findings</h3>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-4 text-gray-400 font-medium">#</th>
                      <th className="text-left py-3 px-4 text-gray-400 font-medium">Type</th>
                      <th className="text-left py-3 px-4 text-gray-400 font-medium">Severity</th>
                      <th className="text-left py-3 px-4 text-gray-400 font-medium">Name</th>
                      <th className="text-left py-3 px-4 text-gray-400 font-medium">Location</th>
                      <th className="text-left py-3 px-4 text-gray-400 font-medium">Tool</th>
                    </tr>
                  </thead>
                  <tbody>
                    {currentScan.findings.map((finding: any, idx: number) => (
                      <tr key={idx} className="border-b border-gray-800 hover:bg-gray-800/50">
                        <td className="py-3 px-4 text-gray-300">{idx + 1}</td>
                        <td className="py-3 px-4 text-gray-300">
                          <span className="px-2 py-1 bg-gray-700 rounded text-xs">
                            {finding.type}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-1 rounded text-xs font-semibold ${
                            finding.severity >= 9.0 ? 'bg-red-900/50 text-red-300' :
                            finding.severity >= 7.0 ? 'bg-orange-900/50 text-orange-300' :
                            finding.severity >= 4.0 ? 'bg-yellow-900/50 text-yellow-300' :
                            'bg-blue-900/50 text-blue-300'
                          }`}>
                            {finding.severity.toFixed(1)}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-300">{finding.name}</td>
                        <td className="py-3 px-4 text-gray-400 text-sm font-mono">
                          {finding.location?.substring(0, 50)}{finding.location?.length > 50 ? '...' : ''}
                        </td>
                        <td className="py-3 px-4 text-gray-400 text-sm">{finding.tool}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* No Findings Message */}
          {(!currentScan.findings || currentScan.findings.length === 0) && (
            <div className="text-center py-8">
              <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-3" />
              <p className="text-gray-400 text-lg">No vulnerabilities found during this scan.</p>
              <p className="text-gray-500 text-sm mt-2">The target appears to be secure against the tests performed.</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
