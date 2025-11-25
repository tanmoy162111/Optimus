import { useState, useEffect } from 'react';
import { api } from '../services/api';
import { Shield, Activity, Target, AlertTriangle } from 'lucide-react';

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
    <div className="p-6">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-green-500 mb-2">
          ⚡ Project Optimus Dashboard
        </h1>
        <p className="text-gray-400">
          AI-Driven Autonomous Penetration Testing Agent
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-blue-500/10 rounded-lg">
              <Activity className="w-6 h-6 text-blue-500" />
            </div>
            <span className="text-2xl font-bold text-blue-500">
              {stats.activeScans}
            </span>
          </div>
          <h3 className="text-gray-400 text-sm">Active Scans</h3>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-green-500/10 rounded-lg">
              <Target className="w-6 h-6 text-green-500" />
            </div>
            <span className="text-2xl font-bold text-green-500">
              {stats.totalFindings}
            </span>
          </div>
          <h3 className="text-gray-400 text-sm">Total Findings</h3>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-red-500/10 rounded-lg">
              <AlertTriangle className="w-6 h-6 text-red-500" />
            </div>
            <span className="text-2xl font-bold text-red-500">
              {stats.criticalFindings}
            </span>
          </div>
          <h3 className="text-gray-400 text-sm">Critical Issues</h3>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="p-3 bg-green-500/10 rounded-lg">
              <Shield className="w-6 h-6 text-green-500" />
            </div>
            <span className="text-2xl font-bold text-green-500">
              {stats.systemHealth === 'healthy' ? '✓' : '✗'}
            </span>
          </div>
          <h3 className="text-gray-400 text-sm">System Status</h3>
        </div>
      </div>

      {/* Welcome Card */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-8">
        <h2 className="text-2xl font-semibold text-green-400 mb-4">
          Welcome to Project Optimus
        </h2>
        <div className="space-y-4 text-gray-300">
          <p>
            Project Optimus is an AI-driven autonomous penetration testing platform that combines:
          </p>
          <ul className="list-disc list-inside space-y-2 ml-4">
            <li>Machine Learning for vulnerability detection</li>
            <li>Reinforcement Learning for intelligent tool selection</li>
            <li>Phase-aware pentesting methodology</li>
            <li>Real-time monitoring and reporting</li>
          </ul>
          <div className="mt-6 pt-6 border-t border-gray-800">
            <h3 className="text-lg font-semibold mb-3 text-green-500">
              Key Features
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-start gap-3">
                <span className="text-green-500">✓</span>
                <div>
                  <strong>6 ML Models</strong>
                  <p className="text-sm text-gray-400">
                    Vuln detection, attack classification, severity prediction
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <span className="text-green-500">✓</span>
                <div>
                  <strong>DQN-based RL Agent</strong>
                  <p className="text-sm text-gray-400">
                    Adaptive tool selection and strategy optimization
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <span className="text-green-500">✓</span>
                <div>
                  <strong>5 Pentesting Phases</strong>
                  <p className="text-sm text-gray-400">
                    Recon → Scan → Exploit → Post-Exploit → Cleanup
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <span className="text-green-500">✓</span>
                <div>
                  <strong>Real-time Updates</strong>
                  <p className="text-sm text-gray-400">
                    WebSocket-based live monitoring
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
