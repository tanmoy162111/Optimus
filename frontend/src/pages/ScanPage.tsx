import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { useScanStore } from '../store/scanStore';
import { Vulnerability } from '../types/scan.types';
import { Play, Square, Loader2, FileText, CheckCircle, ChevronDown, ChevronRight } from 'lucide-react';
import { useWebSocket } from '../hooks/useWebSocket';

export default function ScanPage() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);
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

  const toggleVulnDetails = (vulnIndex: number) => {
    setExpandedVuln(expandedVuln === `${vulnIndex}` ? null : `${vulnIndex}`);
  };

  const getSeverityColor = (severity: number) => {
    if (severity >= 9.0) return 'bg-red-900/50 text-red-300 border-red-800';
    if (severity >= 7.0) return 'bg-orange-900/50 text-orange-300 border-orange-800';
    if (severity >= 4.0) return 'bg-yellow-900/50 text-yellow-300 border-yellow-800';
    return 'bg-blue-900/50 text-blue-300 border-blue-800';
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
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
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

      {/* Unified Report Dashboard */}
      {currentScan && currentScan.status === 'completed' && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center gap-3 mb-6">
            <FileText className="w-6 h-6 text-cyan-400" />
            <h2 className="text-2xl font-semibold text-cyan-400">Security Scan Report</h2>
          </div>

          {/* Executive Summary */}
          <div className="mb-8">
            <h3 className="text-xl font-semibold mb-4 text-cyan-400">Executive Summary</h3>
            
            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
              <div className="bg-red-900/20 border border-red-800 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-red-400">
                  {currentScan.findings?.filter((f: Vulnerability) => f.severity >= 9.0).length || 0}
                </div>
                <div className="text-sm text-gray-400">Critical</div>
              </div>
              
              <div className="bg-orange-900/20 border border-orange-800 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-orange-400">
                  {currentScan.findings?.filter((f: Vulnerability) => f.severity >= 7.0 && f.severity < 9.0).length || 0}
                </div>
                <div className="text-sm text-gray-400">High</div>
              </div>
              
              <div className="bg-yellow-900/20 border border-yellow-800 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-yellow-400">
                  {currentScan.findings?.filter((f: Vulnerability) => f.severity >= 4.0 && f.severity < 7.0).length || 0}
                </div>
                <div className="text-sm text-gray-400">Medium</div>
              </div>
              
              <div className="bg-blue-900/20 border border-blue-800 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-blue-400">
                  {currentScan.findings?.filter((f: Vulnerability) => f.severity < 4.0).length || 0}
                </div>
                <div className="text-sm text-gray-400">Low</div>
              </div>
              
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-gray-200">
                  {currentScan.findings?.length || 0}
                </div>
                <div className="text-sm text-gray-400">Total</div>
              </div>
            </div>
            
            {/* Risk Level */}
            <div className="mb-6">
              <div className="flex items-center gap-2">
                <span className="text-gray-400">Overall Risk Level:</span>
                <span className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  (currentScan.findings?.filter((f: Vulnerability) => f.severity >= 9.0).length || 0) > 0 ? 'bg-red-500 text-white' :
                  (currentScan.findings?.filter((f: Vulnerability) => f.severity >= 7.0).length || 0) > 0 ? 'bg-orange-500 text-white' :
                  (currentScan.findings?.filter((f: Vulnerability) => f.severity >= 4.0).length || 0) > 0 ? 'bg-yellow-500 text-black' :
                  'bg-green-500 text-white'
                }`}>
                  {
                    (currentScan.findings?.filter((f: Vulnerability) => f.severity >= 9.0).length || 0) > 0 ? 'Critical' :
                    (currentScan.findings?.filter((f: Vulnerability) => f.severity >= 7.0).length || 0) > 0 ? 'High' :
                    (currentScan.findings?.filter((f: Vulnerability) => f.severity >= 4.0).length || 0) > 0 ? 'Medium' :
                    'Low'
                  }
                </span>
              </div>
            </div>
          </div>

          {/* Scan Details */}
          <div className="mb-8">
            <h3 className="text-xl font-semibold mb-4 text-cyan-400">Scan Details</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
                <div className="text-gray-400 text-sm mb-1">Target</div>
                <div className="text-gray-200">{currentScan.target}</div>
              </div>
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
                <div className="text-gray-400 text-sm mb-1">Scan ID</div>
                <div className="text-gray-200 font-mono">{currentScan.scan_id}</div>
              </div>
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
                <div className="text-gray-400 text-sm mb-1">Duration</div>
                <div className="text-gray-200">{currentScan.time_elapsed || 0}s</div>
              </div>
              <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-4">
                <div className="text-gray-400 text-sm mb-1">Coverage</div>
                <div className="text-gray-200">{((currentScan.coverage || 0) * 100).toFixed(0)}%</div>
              </div>
            </div>
          </div>

          {/* Tools Used */}
          {currentScan.tools_executed && currentScan.tools_executed.length > 0 && (
            <div className="mb-8">
              <h3 className="text-xl font-semibold mb-4 text-cyan-400">Tools Executed</h3>
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

          {/* Detailed Findings */}
          <div>
            <h3 className="text-xl font-semibold mb-4 text-cyan-400">Vulnerabilities</h3>
            
            {(!currentScan.findings || currentScan.findings.length === 0) ? (
              <div className="text-center py-8">
                <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-3" />
                <p className="text-gray-400 text-lg">No vulnerabilities found during this scan.</p>
                <p className="text-gray-500 text-sm mt-2">The target appears to be secure against the tests performed.</p>
              </div>
            ) : (
              <div className="space-y-4">
                {currentScan.findings.map((finding: Vulnerability, idx: number) => (
                  <div key={idx} className="border border-gray-700 rounded-lg overflow-hidden">
                    <div 
                      className="flex items-center justify-between p-4 bg-gray-800 cursor-pointer hover:bg-gray-750 transition-colors"
                      onClick={() => toggleVulnDetails(idx)}
                    >
                      <div className="flex items-center gap-4">
                        <div className="flex items-center">
                          {expandedVuln === `${idx}` ? (
                            <ChevronDown className="w-5 h-5 text-gray-400" />
                          ) : (
                            <ChevronRight className="w-5 h-5 text-gray-400" />
                          )}
                        </div>
                        <div className="flex items-center gap-3">
                          <span className={`px-2 py-1 rounded text-xs font-semibold border ${getSeverityColor(finding.severity)}`}>
                            {finding.severity.toFixed(1)}
                          </span>
                          <span className="font-medium text-gray-200">{finding.name}</span>
                        </div>
                      </div>
                      <div className="text-sm text-gray-400">
                        {finding.type} • {finding.location?.substring(0, 30)}{finding.location && finding.location.length > 30 ? '...' : ''}
                      </div>
                    </div>
                    
                    {expandedVuln === `${idx}` && (
                      <div className="p-4 bg-gray-850 border-t border-gray-700">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <div>
                            <h4 className="font-semibold text-gray-300 mb-2">Description</h4>
                            <p className="text-gray-400 text-sm mb-4">{finding.name}</p>
                            
                            <h4 className="font-semibold text-gray-300 mb-2">Technical Details</h4>
                            <div className="space-y-2 text-sm">
                              <div className="flex">
                                <span className="text-gray-500 w-24">Location:</span>
                                <span className="text-gray-300">{finding.location || 'N/A'}</span>
                              </div>
                              <div className="flex">
                                <span className="text-gray-500 w-24">Tool:</span>
                                <span className="text-gray-300">{finding.tool || 'N/A'}</span>
                              </div>
                              <div className="flex">
                                <span className="text-gray-500 w-24">Evidence:</span>
                                <span className="text-gray-300">{finding.evidence?.substring(0, 50) || 'N/A'}{finding.evidence && finding.evidence.length > 50 ? '...' : ''}</span>
                              </div>
                            </div>
                          </div>
                          
                          <div>
                            <h4 className="font-semibold text-gray-300 mb-2">Remediation</h4>
                            <div>
                              <p className="text-gray-400 text-sm">{finding.remediation || 'No specific remediation provided'}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Report Actions */}
          <div className="mt-8 pt-6 border-t border-gray-800">
            <h3 className="text-lg font-semibold mb-4 text-cyan-400">Report Actions</h3>
            <div className="flex flex-wrap gap-4">
              <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 
                               text-white text-sm font-semibold rounded-lg transition-colors">
                <FileText className="w-4 h-4" />
                Download PDF Report
              </button>
              <button className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 
                               text-white text-sm font-semibold rounded-lg transition-colors">
                <FileText className="w-4 h-4" />
                Download JSON Report
              </button>
              <Link 
                to={`/report/${currentScan.scan_id}`}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 
                         text-white text-sm font-semibold rounded-lg transition-colors"
              >
                <FileText className="w-4 h-4" />
                View Detailed Report
              </Link>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}