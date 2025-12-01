import React, { useState, useEffect } from 'react';
import { Zap, Brain, Shield, AlertCircle, GitBranch } from 'lucide-react';

interface Decision {
  type: string;
  decision: string;
  confidence?: number;
  reasoning?: string[];
  defenses?: string[];
  timestamp: string;
}

interface Chain {
  id: string;
  description: string;
  severity: number;
  probability: number;
  impact: string;
}

interface Anomaly {
  anomaly_type: string;
  endpoint: string;
  priority: number;
}

interface IntelligencePanelProps {
  scanId?: string;
  wsConnection?: WebSocket;
}

const IntelligencePanel: React.FC<IntelligencePanelProps> = ({ scanId, wsConnection }) => {
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [chains, setChains] = useState<Chain[]>([]);
  const [learningStats, setLearningStats] = useState<any>(null);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [activeTab, setActiveTab] = useState<'decisions' | 'chains' | 'anomalies'>('decisions');

  useEffect(() => {
    if (wsConnection) {
      const handleMessage = (event: MessageEvent) => {
        try {
          const data = JSON.parse(event.data);

          if (data.type === 'intelligence_tool_selection') {
            setDecisions(prev => [...prev, {
              type: 'Tool Selection',
              decision: data.data.tool,
              confidence: data.data.confidence,
              reasoning: data.data.reasoning,
              timestamp: data.timestamp
            }]);
          } else if (data.type === 'intelligence_chains_discovered') {
            setChains(data.data.chains || []);
          } else if (data.type === 'intelligence_anomaly_detected') {
            setAnomalies(prev => [...prev, data.data]);
          } else if (data.type === 'intelligence_adaptation') {
            setDecisions(prev => [...prev, {
              type: 'Adaptation',
              decision: data.data.message,
              defenses: data.data.defenses,
              timestamp: data.timestamp
            }]);
          }
        } catch (e) {
          console.error('Failed to parse intelligence message:', e);
        }
      };

      wsConnection.addEventListener('message', handleMessage);
      return () => wsConnection.removeEventListener('message', handleMessage);
    }
  }, [wsConnection]);

  return (
    <div className="intelligence-panel bg-gray-900 border border-gray-800 rounded-lg p-6 mt-6">
      <div className="flex items-center gap-3 mb-6">
        <Brain className="w-6 h-6 text-purple-400" />
        <h2 className="text-2xl font-bold text-purple-400">í·  Intelligence Hub</h2>
      </div>

      {/* Tabs */}
      <div className="flex gap-4 mb-6 border-b border-gray-700">
        <button
          onClick={() => setActiveTab('decisions')}
          className={`px-4 py-2 font-medium transition-colors ${
            activeTab === 'decisions'
              ? 'text-purple-400 border-b-2 border-purple-400'
              : 'text-gray-400 hover:text-gray-300'
          }`}
        >
          <Zap className="w-4 h-4 inline mr-2" />
          Decisions ({decisions.length})
        </button>
        <button
          onClick={() => setActiveTab('chains')}
          className={`px-4 py-2 font-medium transition-colors ${
            activeTab === 'chains'
              ? 'text-purple-400 border-b-2 border-purple-400'
              : 'text-gray-400 hover:text-gray-300'
          }`}
        >
          <GitBranch className="w-4 h-4 inline mr-2" />
          Chains ({chains.length})
        </button>
        <button
          onClick={() => setActiveTab('anomalies')}
          className={`px-4 py-2 font-medium transition-colors ${
            activeTab === 'anomalies'
              ? 'text-purple-400 border-b-2 border-purple-400'
              : 'text-gray-400 hover:text-gray-300'
          }`}
        >
          <AlertCircle className="w-4 h-4 inline mr-2" />
          Anomalies ({anomalies.length})
        </button>
      </div>

      {/* Content */}
      <div className="space-y-4">
        {activeTab === 'decisions' && (
          <div className="decisions-section">
            {decisions.length === 0 ? (
              <p className="text-gray-500 text-center py-8">No intelligence decisions yet...</p>
            ) : (
              decisions.slice(-10).map((d, i) => (
                <div key={i} className="decision-card bg-gray-800/50 border border-gray-700 rounded p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-semibold text-purple-300">{d.type}</div>
                    {d.confidence && (
                      <div className="text-sm text-gray-400">
                        {(d.confidence * 100).toFixed(0)}% confidence
                      </div>
                    )}
                  </div>
                  <div className="text-gray-100 font-mono text-sm mb-2">{d.decision}</div>
                  {d.reasoning && (
                    <div className="reasoning text-xs text-gray-400">
                      {d.reasoning.map((r, j) => (
                        <div key={j} className="ml-4">â€¢ {r}</div>
                      ))}
                    </div>
                  )}
                  {d.defenses && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {d.defenses.map((def, j) => (
                        <span key={j} className="px-2 py-1 bg-red-900/30 text-red-300 rounded text-xs">
                          {def}
                        </span>
                      ))}
                    </div>
                  )}
                  <div className="text-xs text-gray-500 mt-2">{new Date(d.timestamp).toLocaleTimeString()}</div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'chains' && (
          <div className="chains-section">
            {chains.length === 0 ? (
              <p className="text-gray-500 text-center py-8">No attack chains discovered...</p>
            ) : (
              chains.map((chain, i) => (
                <div key={i} className="chain-card bg-gray-800/50 border border-yellow-700 rounded p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <Shield className="w-4 h-4 text-yellow-400" />
                    <div className="font-semibold text-yellow-300">{chain.description}</div>
                  </div>
                  <div className="grid grid-cols-3 gap-4 mt-3">
                    <div>
                      <div className="text-xs text-gray-400">Severity</div>
                      <div className={`font-bold ${
                        chain.severity >= 8 ? 'text-red-400' :
                        chain.severity >= 5 ? 'text-orange-400' :
                        'text-yellow-400'
                      }`}>
                        {chain.severity.toFixed(1)}/10
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-400">Success Rate</div>
                      <div className="font-bold text-blue-400">
                        {(chain.probability * 100).toFixed(0)}%
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-gray-400">Impact</div>
                      <div className="font-bold text-gray-200 text-sm">{chain.impact}</div>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'anomalies' && (
          <div className="anomalies-section">
            {anomalies.length === 0 ? (
              <p className="text-gray-500 text-center py-8">No anomalies detected...</p>
            ) : (
              anomalies.map((a, i) => (
                <div
                  key={i}
                  className={`anomaly-card border rounded p-4 ${
                    a.priority >= 8
                      ? 'bg-red-900/20 border-red-700'
                      : a.priority >= 5
                      ? 'bg-orange-900/20 border-orange-700'
                      : 'bg-yellow-900/20 border-yellow-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-semibold text-gray-100">{a.anomaly_type}</div>
                    <div className={`font-bold text-sm ${
                      a.priority >= 8 ? 'text-red-400' :
                      a.priority >= 5 ? 'text-orange-400' :
                      'text-yellow-400'
                    }`}>
                      Priority {a.priority}/10
                    </div>
                  </div>
                  <div className="text-sm text-gray-300 font-mono">{a.endpoint}</div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default IntelligencePanel;
