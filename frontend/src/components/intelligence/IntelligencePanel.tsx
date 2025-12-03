import React, { useState, useEffect } from 'react';
import { Card, Badge } from '@/components/ui';
import { 
  Brain, 
  Zap, 
  Link, 
  AlertTriangle, 
  CheckCircle, 
  Clock,
  Target,
  Shield
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface IntelligenceEvent {
  id: string;
  timestamp: string;
  type: 'decision' | 'chain' | 'anomaly' | 'adaptation' | 'learning';
  message: string;
  confidence?: number;
  details?: any;
}

interface IntelligencePanelProps {
  scanId: string;
  wsConnection?: any;
  className?: string;
}

export const IntelligencePanel: React.FC<IntelligencePanelProps> = ({
  scanId,
  wsConnection,
  className,
}) => {
  const [events, setEvents] = useState<IntelligenceEvent[]>([]);
  const [activeTab, setActiveTab] = useState<'decisions' | 'chains' | 'anomalies'>('decisions');

  // Mock data for demonstration
  const mockEvents: IntelligenceEvent[] = [
    {
      id: '1',
      timestamp: new Date().toISOString(),
      type: 'decision',
      message: 'Selected nuclei for XSS scanning based on target analysis',
      confidence: 0.92,
    },
    {
      id: '2',
      timestamp: new Date(Date.now() - 60000).toISOString(),
      type: 'chain',
      message: 'Discovered potential SQL injection -> privilege escalation chain',
      confidence: 0.87,
    },
    {
      id: '3',
      timestamp: new Date(Date.now() - 120000).toISOString(),
      type: 'anomaly',
      message: 'Unusual response pattern detected in /admin endpoint',
      confidence: 0.95,
    },
    {
      id: '4',
      timestamp: new Date(Date.now() - 180000).toISOString(),
      type: 'adaptation',
      message: 'Switching to stealth mode due to WAF detection',
      confidence: 0.89,
    },
  ];

  useEffect(() => {
    // In a real implementation, we would connect to WebSocket for real-time updates
    setEvents(mockEvents);
    
    // Simulate real-time updates
    const interval = setInterval(() => {
      if (events.length > 10) {
        setEvents(prev => prev.slice(0, 10));
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [scanId]);

  const getTypeConfig = (type: IntelligenceEvent['type']) => {
    const configs = {
      decision: {
        icon: Brain,
        label: 'Decision',
        color: 'text-neon-green',
        bg: 'bg-neon-green/10',
      },
      chain: {
        icon: Link,
        label: 'Chain',
        color: 'text-neon-cyan',
        bg: 'bg-neon-cyan/10',
      },
      anomaly: {
        icon: AlertTriangle,
        label: 'Anomaly',
        color: 'text-neon-yellow',
        bg: 'bg-neon-yellow/10',
      },
      adaptation: {
        icon: Shield,
        label: 'Adaptation',
        color: 'text-neon-purple',
        bg: 'bg-neon-purple/10',
      },
      learning: {
        icon: Zap,
        label: 'Learning',
        color: 'text-neon-pink',
        bg: 'bg-neon-pink/10',
      },
    };
    return configs[type];
  };

  const filteredEvents = events.filter(event => {
    if (activeTab === 'decisions') return event.type === 'decision' || event.type === 'adaptation';
    if (activeTab === 'chains') return event.type === 'chain';
    if (activeTab === 'anomalies') return event.type === 'anomaly';
    return true;
  });

  return (
    <Card variant="default" className={cn('p-4', className)}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Brain className="w-5 h-5 text-neon-green" />
          <h3 className="text-white font-medium">Intelligence Feed</h3>
        </div>
        <Badge variant="success" size="sm">
          Active
        </Badge>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-cyber-light/20">
        <button
          onClick={() => setActiveTab('decisions')}
          className={cn(
            'px-3 py-2 text-sm font-medium transition-colors',
            activeTab === 'decisions'
              ? 'text-neon-green border-b-2 border-neon-green'
              : 'text-gray-500 hover:text-gray-300'
          )}
        >
          Decisions
        </button>
        <button
          onClick={() => setActiveTab('chains')}
          className={cn(
            'px-3 py-2 text-sm font-medium transition-colors',
            activeTab === 'chains'
              ? 'text-neon-cyan border-b-2 border-neon-cyan'
              : 'text-gray-500 hover:text-gray-300'
          )}
        >
          Chains
        </button>
        <button
          onClick={() => setActiveTab('anomalies')}
          className={cn(
            'px-3 py-2 text-sm font-medium transition-colors',
            activeTab === 'anomalies'
              ? 'text-neon-yellow border-b-2 border-neon-yellow'
              : 'text-gray-500 hover:text-gray-300'
          )}
        >
          Anomalies
        </button>
      </div>

      {/* Events List */}
      <div className="space-y-3 max-h-96 overflow-y-auto">
        {filteredEvents.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            <Brain className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p>No intelligence events yet</p>
          </div>
        ) : (
          filteredEvents.map((event) => {
            const config = getTypeConfig(event.type);
            const Icon = config.icon;
            
            return (
              <div
                key={event.id}
                className="p-3 rounded-lg border border-cyber-light/10 bg-cyber-dark/50 hover:bg-cyber-dark/70 transition-colors"
              >
                <div className="flex items-start gap-3">
                  <div className={cn('p-2 rounded-lg', config.bg)}>
                    <Icon className={cn('w-4 h-4', config.color)} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-gray-400">
                        {new Date(event.timestamp).toLocaleTimeString()}
                      </span>
                      {event.confidence && (
                        <Badge variant="default" size="xs">
                          {Math.round(event.confidence * 100)}%
                        </Badge>
                      )}
                    </div>
                    <p className="text-sm text-white mb-1">{event.message}</p>
                    {event.details && (
                      <p className="text-xs text-gray-500 truncate">
                        {JSON.stringify(event.details)}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </Card>
  );
};

export default IntelligencePanel;