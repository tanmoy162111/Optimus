import React, { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  FileText,
  Download,
  RefreshCw,
  AlertTriangle,
  Clock,
  Target,
  Shield,
  ArrowLeft,
  Printer,
} from 'lucide-react';
import { formatDate, formatDuration, countBySeverity } from '@/lib/utils';
import { api } from '@/services/api';
import {
  Card,
  Button,
  Badge,
  Spinner,
  FindingsPanel,
  SeverityDistribution,
} from '@/components';
import type { Scan } from '@/types';

// ============================================
// Reports List Page
// ============================================

export const ReportsPage: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.scan.list({ limit: 50 });
      setScans(data.items);
    } catch (err) {
      setError('Failed to load reports');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <Spinner size="lg" />
          <p className="text-gray-400 mt-4">Loading reports...</p>
        </div>
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
            Reports
          </h1>
          <p className="text-gray-400">View and export scan reports</p>
        </div>

        <Button variant="secondary" size="sm" onClick={loadScans}>
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </motion.div>

      {/* Reports Grid */}
      {error ? (
        <Card variant="default" className="p-6 text-center">
          <AlertTriangle className="w-12 h-12 text-neon-orange mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Error</h2>
          <p className="text-gray-400 mb-4">{error}</p>
          <Button variant="secondary" onClick={loadScans}>
            Try Again
          </Button>
        </Card>
      ) : scans.length === 0 ? (
        <Card variant="default" className="p-6 text-center">
          <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">No reports yet</h2>
          <p className="text-gray-400 mb-4">
            Complete a scan to generate a report
          </p>
          <Link to="/scan">
            <Button variant="primary">
              <Target className="w-4 h-4" />
              Start a Scan
            </Button>
          </Link>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scans.map((scan) => (
            <ReportCard key={scan.scan_id} scan={scan} />
          ))}
        </div>
      )}
    </div>
  );
};

// ============================================
// Report Card Component
// ============================================

interface ReportCardProps {
  scan: Scan;
}

const ReportCard: React.FC<ReportCardProps> = ({ scan }) => {
  const counts = countBySeverity(scan.findings);

  const statusConfig = {
    completed: { color: '#00d4ff', label: 'Completed' },
    running: { color: '#00ff9d', label: 'Running' },
    stopped: { color: '#a0a0b0', label: 'Stopped' },
    error: { color: '#ff0055', label: 'Error' },
    paused: { color: '#ffcc00', label: 'Paused' },
    initializing: { color: '#9d00ff', label: 'Initializing' },
  };

  const config = statusConfig[scan.status];

  return (
    <Link to={`/report/${scan.scan_id}`}>
      <Card
        variant="default"
        className="p-4 h-full hover:border-neon-green/30 transition-all cursor-pointer group"
      >
        <div className="flex items-start justify-between mb-4">
          <div className="flex-1 min-w-0">
            <h3 className="text-white font-medium truncate group-hover:text-neon-green transition-colors">
              {scan.target}
            </h3>
            <p className="text-xs text-gray-500">{formatDate(scan.start_time)}</p>
          </div>
          <Badge
            variant={
              scan.status === 'completed'
                ? 'success'
                : scan.status === 'error'
                ? 'danger'
                : 'info'
            }
            size="sm"
          >
            {config.label}
          </Badge>
        </div>

        {/* Severity Mini Bar */}
        {scan.findings.length > 0 && (
          <div className="h-2 rounded-full overflow-hidden flex mb-4 bg-cyber-medium">
            {counts.critical > 0 && (
              <div
                className="h-full"
                style={{
                  width: `${(counts.critical / scan.findings.length) * 100}%`,
                  backgroundColor: '#ff0055',
                }}
              />
            )}
            {counts.high > 0 && (
              <div
                className="h-full"
                style={{
                  width: `${(counts.high / scan.findings.length) * 100}%`,
                  backgroundColor: '#ff6600',
                }}
              />
            )}
            {counts.medium > 0 && (
              <div
                className="h-full"
                style={{
                  width: `${(counts.medium / scan.findings.length) * 100}%`,
                  backgroundColor: '#ffcc00',
                }}
              />
            )}
            {counts.low > 0 && (
              <div
                className="h-full"
                style={{
                  width: `${(counts.low / scan.findings.length) * 100}%`,
                  backgroundColor: '#00d4ff',
                }}
              />
            )}
          </div>
        )}

        <div className="flex items-center justify-between text-sm">
          <div className="flex items-center gap-4 text-gray-500">
            <span className="flex items-center gap-1">
              <Shield className="w-3 h-3" />
              {scan.findings.length}
            </span>
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {formatDuration(scan.time_elapsed)}
            </span>
          </div>

          {counts.critical > 0 && (
            <span className="text-[#ff0055] font-medium">
              {counts.critical} critical
            </span>
          )}
        </div>
      </Card>
    </Link>
  );
};

// ============================================
// Report Detail Page
// ============================================

export const ReportDetailPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (scanId) {
      loadScan();
    }
  }, [scanId]);

  const loadScan = async () => {
    if (!scanId) return;
    
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.scan.getResults(scanId);
      setScan(data);
    } catch (err) {
      setError('Failed to load report');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExport = async (format: 'json' | 'pdf' | 'html') => {
    if (!scanId) return;
    
    try {
      const blob = await api.reports.download(scanId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report-${scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <Spinner size="lg" />
          <p className="text-gray-400 mt-4">Loading report...</p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Card variant="default" className="p-6 max-w-md text-center">
          <AlertTriangle className="w-12 h-12 text-neon-orange mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Error</h2>
          <p className="text-gray-400 mb-4">{error || 'Report not found'}</p>
          <Link to="/reports">
            <Button variant="secondary">
              <ArrowLeft className="w-4 h-4" />
              Back to Reports
            </Button>
          </Link>
        </Card>
      </div>
    );
  }

  const counts = countBySeverity(scan.findings);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <Link
          to="/reports"
          className="inline-flex items-center gap-2 text-gray-400 hover:text-white mb-4 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Reports
        </Link>

        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h1 className="text-2xl md:text-3xl font-bold text-white display-text mb-2">
              {scan.target}
            </h1>
            <p className="text-gray-400">
              Scanned on {formatDate(scan.start_time)} • Duration:{' '}
              {formatDuration(scan.time_elapsed)}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" onClick={() => handleExport('json')}>
              <Download className="w-4 h-4" />
              JSON
            </Button>
            <Button variant="secondary" size="sm" onClick={() => handleExport('html')}>
              <Download className="w-4 h-4" />
              HTML
            </Button>
            <Button variant="secondary" size="sm" onClick={() => window.print()}>
              <Printer className="w-4 h-4" />
              Print
            </Button>
          </div>
        </div>
      </motion.div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <SummaryStatCard
          label="Total Findings"
          value={scan.findings.length}
          color="#00ff9d"
        />
        <SummaryStatCard
          label="Critical"
          value={counts.critical}
          color="#ff0055"
        />
        <SummaryStatCard
          label="High"
          value={counts.high}
          color="#ff6600"
        />
        <SummaryStatCard
          label="Medium"
          value={counts.medium}
          color="#ffcc00"
        />
        <SummaryStatCard
          label="Low"
          value={counts.low}
          color="#00d4ff"
        />
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar */}
        <div className="space-y-4">
          {/* Scan Info */}
          <Card variant="default" className="p-4">
            <h3 className="text-sm font-medium text-white mb-4">Scan Details</h3>
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Status</span>
                <Badge
                  variant={scan.status === 'completed' ? 'success' : 'info'}
                  size="sm"
                >
                  {scan.status}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Phase</span>
                <span className="text-white">{scan.phase}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Coverage</span>
                <span className="text-white">{(scan.coverage * 100).toFixed(0)}%</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Tools Used</span>
                <span className="text-white">{scan.tools_executed.length}</span>
              </div>
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

        {/* Findings */}
        <div className="lg:col-span-3">
          <Card variant="default" className="p-4">
            <FindingsPanel
              findings={scan.findings}
              maxHeight="calc(100vh - 400px)"
            />
          </Card>
        </div>
      </div>
    </div>
  );
};

// ============================================
// Summary Stat Card
// ============================================

interface SummaryStatCardProps {
  label: string;
  value: number;
  color: string;
}

const SummaryStatCard: React.FC<SummaryStatCardProps> = ({
  label,
  value,
  color,
}) => {
  return (
    <Card variant="default" className="p-4 text-center">
      <p className="text-3xl font-bold mb-1" style={{ color }}>
        {value}
      </p>
      <p className="text-xs text-gray-500">{label}</p>
    </Card>
  );
};

export default ReportsPage;
