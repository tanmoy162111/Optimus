import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Download,
  Filter,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react';
import { cn, downloadFile } from '@/lib/utils';
import { api } from '@/services/api';
import {
  Card,
  Button,
  Badge,
  Spinner,
  FindingsPanel,
  SeverityDistribution,
} from '@/components';
import type { Vulnerability, Scan } from '@/types';

// ============================================
// Findings Page
// ============================================

export const FindingsPage: React.FC = () => {
  const [findings, setFindings] = useState<Vulnerability[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const scansResponse = await api.scan.list({ limit: 20 });
      setScans(scansResponse.items);

      // Aggregate all findings
      const allFindings: Vulnerability[] = [];
      for (const scan of scansResponse.items) {
        if (scan.findings) {
          allFindings.push(...scan.findings);
        }
      }
      setFindings(allFindings);
    } catch (err) {
      setError('Failed to load findings');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  // Filter findings by selected scan
  const filteredFindings = selectedScan
    ? scans.find((s) => s.scan_id === selectedScan)?.findings || []
    : findings;

  // Calculate severity counts
  const counts = {
    critical: filteredFindings.filter((f) => f.severity >= 9.0).length,
    high: filteredFindings.filter((f) => f.severity >= 7.0 && f.severity < 9.0).length,
    medium: filteredFindings.filter((f) => f.severity >= 4.0 && f.severity < 7.0).length,
    low: filteredFindings.filter((f) => f.severity > 0 && f.severity < 4.0).length,
    info: filteredFindings.filter((f) => f.severity === 0).length,
  };

  // Export findings
  const exportFindings = () => {
    const data = JSON.stringify(filteredFindings, null, 2);
    downloadFile(data, `findings-${Date.now()}.json`);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <Spinner size="lg" />
          <p className="text-gray-400 mt-4">Loading findings...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Card variant="default" padding="lg" className="max-w-md text-center">
          <AlertTriangle className="w-12 h-12 text-neon-orange mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Error</h2>
          <p className="text-gray-400 mb-4">{error}</p>
          <Button variant="outline" onClick={loadData}>
            <RefreshCw className="w-4 h-4" />
            Try Again
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row md:items-center md:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-white display-text mb-2">
            Findings
          </h1>
          <p className="text-gray-400">
            All discovered vulnerabilities across your scans
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button variant="secondary" size="sm" onClick={loadData}>
            <RefreshCw className="w-4 h-4" />
            Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={exportFindings}>
            <Download className="w-4 h-4" />
            Export
          </Button>
        </div>
      </motion.div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatBox
          label="Critical"
          count={counts.critical}
          color="#ff0055"
        />
        <StatBox
          label="High"
          count={counts.high}
          color="#ff6600"
        />
        <StatBox
          label="Medium"
          count={counts.medium}
          color="#ffcc00"
        />
        <StatBox
          label="Low"
          count={counts.low}
          color="#00d4ff"
        />
        <StatBox
          label="Info"
          count={counts.info}
          color="#a0a0b0"
        />
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Filters Sidebar */}
        <div className="space-y-4">
          <Card variant="default" padding="md">
            <div className="flex items-center gap-2 mb-4">
              <Filter className="w-4 h-4 text-gray-400" />
              <h3 className="text-sm font-medium text-white">Filter by Scan</h3>
            </div>

            <div className="space-y-2">
              <button
                onClick={() => setSelectedScan(null)}
                className={cn(
                  'w-full text-left px-3 py-2 rounded-lg text-sm transition-colors',
                  !selectedScan
                    ? 'bg-neon-green/10 text-neon-green'
                    : 'text-gray-400 hover:bg-cyber-light/30'
                )}
              >
                All Scans ({findings.length})
              </button>

              {scans.map((scan) => (
                <button
                  key={scan.scan_id}
                  onClick={() => setSelectedScan(scan.scan_id)}
                  className={cn(
                    'w-full text-left px-3 py-2 rounded-lg text-sm transition-colors',
                    selectedScan === scan.scan_id
                      ? 'bg-neon-green/10 text-neon-green'
                      : 'text-gray-400 hover:bg-cyber-light/30'
                  )}
                >
                  <div className="truncate">{scan.target}</div>
                  <div className="text-xs text-gray-600">
                    {scan.findings.length} findings
                  </div>
                </button>
              ))}
            </div>
          </Card>

          {/* Severity Distribution */}
          <SeverityDistribution
            critical={counts.critical}
            high={counts.high}
            medium={counts.medium}
            low={counts.low}
            info={counts.info}
          />
        </div>

        {/* Findings List */}
        <div className="lg:col-span-3">
          {filteredFindings.length === 0 ? (
            <Card variant="default" padding="lg" className="text-center">
              <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h2 className="text-xl font-bold text-white mb-2">
                No findings yet
              </h2>
              <p className="text-gray-400">
                Run a scan to discover vulnerabilities
              </p>
            </Card>
          ) : (
            <Card variant="default" padding="md">
              <FindingsPanel
                findings={filteredFindings}
                maxHeight="calc(100vh - 300px)"
              />
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

// ============================================
// Stat Box Component
// ============================================

interface StatBoxProps {
  label: string;
  count: number;
  color: string;
}

const StatBox: React.FC<StatBoxProps> = ({ label, count, color }) => {
  return (
    <Card variant="default" padding="md" className="text-center">
      <div
        className="text-3xl font-bold mb-1"
        style={{ color }}
      >
        {count}
      </div>
      <div className="text-xs text-gray-500">{label}</div>
    </Card>
  );
};

export default FindingsPage;
