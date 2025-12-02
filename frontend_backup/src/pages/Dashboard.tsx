import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Shield, Activity, Target, AlertTriangle, Zap } from 'lucide-react';
import { io } from 'socket.io-client';

export default function Dashboard() {
  const [stats, setStats] = useState({
    activeScans: 0,
    totalFindings: 0,
    criticalFindings: 0,
    systemHealth: 'healthy'
  });

  // Dashboard scan control state
  const [targetInput, setTargetInput] = useState('');
  const [scan, setScan] = useState<any | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [executing, setExecuting] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  // Join WebSocket room for live tool output when a scan is active
  useEffect(() => {
    if (!scan) return;
    const s = io(import.meta.env.VITE_API_URL || 'http://localhost:5000');
    s.emit('join_scan', { scan_id: scan.scan_id });
    s.on('tool_execution_start', (evt: any) => {
      setLogs((prev) => [...prev, `▶ ${evt.tool} started on ${evt.target}`]);
    });
    s.on('tool_output', (evt: any) => {
      if (evt.output) setLogs((prev) => [...prev, evt.output]);
    });
    s.on('tool_execution_complete', (evt: any) => {
      setLogs((prev) => [...prev, `✓ ${evt.tool} completed (success=${evt.success}) in ${typeof evt.execution_time === 'number' ? evt.execution_time.toFixed(2) : evt.execution_time}s`]);
      setExecuting(false);
    });
    s.on('error', (evt: any) => {
      setLogs((prev) => [...prev, `✗ Error: ${evt.error}`]);
      setExecuting(false);
    });
    return () => {
      s.disconnect();
    };
  }, [scan]);

  const loadDashboardData = async () => {
    try {
      const [scansRes] = await Promise.all([
        api.scan.list()
      ]);
      
      setStats({
        activeScans: scansRes.data.active_count || 0,
        totalFindings: 0,
        criticalFindings: 0,
        systemHealth: 'healthy'
      });
    } catch (error) {
      console.error('Error loading dashboard:', error);
    }
  };

  // Start a scan directly from dashboard
  const startDashboardScan = async () => {
    if (!targetInput.trim()) {
      alert('Enter target (use http:// for web targets)');
      return;
    }
    try {
      const res = await api.scan.start(targetInput.trim());
      setScan(res.data);
      setLogs((prev) => [...prev, `Scan started for ${res.data.target}`]);
    } catch (e: any) {
      alert(e?.response?.data?.error || 'Failed to start scan');
    }
  };

  // Execute a tool against current dashboard scan
  const executeDashboardTool = async (tool: string) => {
    if (!scan) {
      alert('Start a scan first');
      return;
    }
    setExecuting(true);
    try {
      await api.scan.executeTool(scan.scan_id, tool, scan.target);
    } catch (e: any) {
      setExecuting(false);
      alert(e?.response?.data?.error || `Failed to execute ${tool}`);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 p-6 relative overflow-hidden">
      {/* Animated background effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" style={{animationDelay: '1s'}}></div>
      </div>

      <div className="relative z-10 max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8 text-center">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-12 h-12 text-cyan-400 animate-pulse" />
            <h1 className="text-5xl font-bold bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent">
              Optimus Dashboard
            </h1>
          </div>
          <p className="text-cyan-300/80 text-lg">
            AI-Driven Autonomous Penetration Testing Agent
          </p>
        </div>

        {/* Stats Grid - Cyber style cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {/* Active Scans */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-blue-500/20 to-cyan-500/20 rounded-lg blur-sm group-hover:blur-md transition-all"></div>
            <div className="relative bg-gray-900/90 border border-cyan-500/50 rounded-lg p-6 backdrop-blur-sm hover:border-cyan-400 transition-all">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-blue-500/20 rounded-lg border border-blue-500/50">
                  <Activity className="w-6 h-6 text-blue-400" />
                </div>
                <span className="text-4xl font-bold text-blue-400 font-mono">
                  {stats.activeScans.toString().padStart(2, '0')}
                </span>
              </div>
              <h3 className="text-gray-400 text-sm uppercase tracking-wider">Active Scans</h3>
              <div className="mt-2 h-1 bg-blue-500/20 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-blue-500 to-cyan-500 w-3/4 animate-pulse"></div>
              </div>
            </div>
          </div>

          {/* Total Findings */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-green-500/20 to-emerald-500/20 rounded-lg blur-sm group-hover:blur-md transition-all"></div>
            <div className="relative bg-gray-900/90 border border-green-500/50 rounded-lg p-6 backdrop-blur-sm hover:border-green-400 transition-all">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-green-500/20 rounded-lg border border-green-500/50">
                  <Target className="w-6 h-6 text-green-400" />
                </div>
                <span className="text-4xl font-bold text-green-400 font-mono">
                  {stats.totalFindings.toString().padStart(2, '0')}
                </span>
              </div>
              <h3 className="text-gray-400 text-sm uppercase tracking-wider">Total Findings</h3>
              <div className="mt-2 h-1 bg-green-500/20 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-green-500 to-emerald-500 w-1/2 animate-pulse"></div>
              </div>
            </div>
          </div>

          {/* Critical Issues */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-red-500/20 to-orange-500/20 rounded-lg blur-sm group-hover:blur-md transition-all"></div>
            <div className="relative bg-gray-900/90 border border-red-500/50 rounded-lg p-6 backdrop-blur-sm hover:border-red-400 transition-all">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-red-500/20 rounded-lg border border-red-500/50">
                  <AlertTriangle className="w-6 h-6 text-red-400" />
                </div>
                <span className="text-4xl font-bold text-red-400 font-mono">
                  {stats.criticalFindings.toString().padStart(2, '0')}
                </span>
              </div>
              <h3 className="text-gray-400 text-sm uppercase tracking-wider">Critical Issues</h3>
              <div className="mt-2 h-1 bg-red-500/20 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-red-500 to-orange-500 w-1/4 animate-pulse"></div>
              </div>
            </div>
          </div>

          {/* System Status */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/20 to-blue-500/20 rounded-lg blur-sm group-hover:blur-md transition-all"></div>
            <div className="relative bg-gray-900/90 border border-cyan-500/50 rounded-lg p-6 backdrop-blur-sm hover:border-cyan-400 transition-all">
              <div className="flex items-center justify-between mb-4">
                <div className="p-3 bg-cyan-500/20 rounded-lg border border-cyan-500/50">
                  <Shield className="w-6 h-6 text-cyan-400" />
                </div>
                <span className="text-4xl font-bold text-cyan-400">
                  {stats.systemHealth === 'healthy' ? '✓' : '✗'}
                </span>
              </div>
              <h3 className="text-gray-400 text-sm uppercase tracking-wider">System Status</h3>
              <div className="mt-2 h-1 bg-cyan-500/20 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 w-full animate-pulse"></div>
              </div>
            </div>
          </div>
        </div>

        {/* Main content cards */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Welcome Card */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-lg blur-sm"></div>
            <div className="relative bg-gray-900/90 border border-blue-500/30 rounded-lg p-8 backdrop-blur-sm">
              <div className="flex items-center gap-3 mb-6">
                <Zap className="w-8 h-8 text-cyan-400" />
                <h2 className="text-2xl font-bold text-cyan-400">Welcome to Optimus</h2>
              </div>
              <div className="space-y-4 text-gray-300">
                <p className="text-gray-400">
                  Optimus is an AI-driven autonomous penetration testing platform that combines:
                </p>
                <ul className="space-y-3">
                  <li className="flex items-start gap-3">
                    <span className="text-cyan-400 mt-1">▹</span>
                    <span>Machine Learning for vulnerability detection</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="text-cyan-400 mt-1">▹</span>
                    <span>Reinforcement Learning for intelligent tool selection</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="text-cyan-400 mt-1">▹</span>
                    <span>Phase-aware pentesting methodology</span>
                  </li>
                  <li className="flex items-start gap-3">
                    <span className="text-cyan-400 mt-1">▹</span>
                    <span>Real-time monitoring and reporting</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>

          {/* Key Features + Scan Control Card */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-purple-500/10 to-pink-500/10 rounded-lg blur-sm"></div>
            <div className="relative bg-gray-900/90 border border-purple-500/30 rounded-lg p-8 backdrop-blur-sm">
              <h3 className="text-2xl font-bold mb-6 text-purple-400">Quick Scan Control</h3>

              {/* Target input + start */}
              <div className="space-y-4 mb-6">
                <label className="block text-sm font-medium text-gray-300">Target</label>
                <input
                  type="text"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  placeholder="http://<ip-or-host>"
                  className="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-lg text-gray-100 focus:outline-none focus:ring-2 focus:ring-purple-500"
                />
                <div className="flex gap-3">
                  <button
                    onClick={startDashboardScan}
                    className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded"
                  >Start Scan</button>
                  {scan && (
                    <span className="text-sm text-gray-400">Scan ID: <span className="text-gray-200 font-mono">{scan.scan_id}</span></span>
                  )}
                </div>
              </div>

              {/* Tool execution */}
              <div className="space-y-3">
                <h4 className="text-lg font-semibold text-purple-300">Execute Tools</h4>
                <div className="flex flex-wrap gap-2">
                  {['nmap','nuclei','nikto','sqlmap','commix'].map((t) => (
                    <button
                      key={t}
                      disabled={!scan || executing}
                      onClick={() => executeDashboardTool(t)}
                      className={`px-3 py-2 rounded text-white ${!scan ? 'bg-gray-700 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700'}`}
                    >{t}</button>
                  ))}
                </div>
              </div>

              {/* Live output */}
              <div className="mt-6">
                <h4 className="text-lg font-semibold text-purple-300 mb-2">Live Output</h4>
                <div className="h-48 overflow-auto bg-black/60 border border-gray-700 rounded p-3 font-mono text-sm text-gray-200">
                  {logs.length === 0 ? (
                    <div className="text-gray-500">No output yet. Start a scan and run a tool.</div>
                  ) : (
                    logs.slice(-200).map((line, idx) => (
                      <div key={idx} className="whitespace-pre-wrap">{line}</div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
