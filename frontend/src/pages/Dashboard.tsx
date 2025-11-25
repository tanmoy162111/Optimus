import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Shield, Activity, Target, AlertTriangle, Zap } from 'lucide-react';

export default function Dashboard() {
  const [stats, setStats] = useState({
    activeScans: 0,
    totalFindings: 0,
    criticalFindings: 0,
    systemHealth: 'healthy'
  });

  useEffect(() => {
    loadDashboardData();
  }, []);

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

          {/* Key Features Card */}
          <div className="relative group">
            <div className="absolute inset-0 bg-gradient-to-r from-purple-500/10 to-pink-500/10 rounded-lg blur-sm"></div>
            <div className="relative bg-gray-900/90 border border-purple-500/30 rounded-lg p-8 backdrop-blur-sm">
              <h3 className="text-2xl font-bold mb-6 text-purple-400">Key Features</h3>
              <div className="grid grid-cols-1 gap-4">
                <div className="flex items-start gap-3 p-4 bg-purple-500/10 rounded-lg border border-purple-500/20">
                  <span className="text-purple-400 text-xl">◆</span>
                  <div>
                    <strong className="text-purple-300">6 ML Models</strong>
                    <p className="text-sm text-gray-400 mt-1">
                      Vuln detection, attack classification, severity prediction
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3 p-4 bg-blue-500/10 rounded-lg border border-blue-500/20">
                  <span className="text-blue-400 text-xl">◆</span>
                  <div>
                    <strong className="text-blue-300">DQN-based RL Agent</strong>
                    <p className="text-sm text-gray-400 mt-1">
                      Adaptive tool selection and strategy optimization
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3 p-4 bg-cyan-500/10 rounded-lg border border-cyan-500/20">
                  <span className="text-cyan-400 text-xl">◆</span>
                  <div>
                    <strong className="text-cyan-300">5 Pentesting Phases</strong>
                    <p className="text-sm text-gray-400 mt-1">
                      Recon → Scan → Exploit → Post-Exploit → Cleanup
                    </p>
                  </div>
                </div>
                <div className="flex items-start gap-3 p-4 bg-green-500/10 rounded-lg border border-green-500/20">
                  <span className="text-green-400 text-xl">◆</span>
                  <div>
                    <strong className="text-green-300">Real-time Updates</strong>
                    <p className="text-sm text-gray-400 mt-1">
                      WebSocket-based live monitoring
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
