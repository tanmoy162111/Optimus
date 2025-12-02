import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Target,
  ArrowRight,
  Clock,
  Activity,
  Shield,
  Zap,
  TrendingUp,
  AlertTriangle,
} from 'lucide-react';
import { cn, formatDuration, formatDate, countBySeverity } from '@/lib/utils';
import { useDashboardData, useWebSocket, useScanEvents } from '@/hooks';
import { useScanStore } from '@/stores';
import {
  Card,
  Button,
  Badge,
  Spinner,
  StatsGrid,
  SeverityDistribution,
  ScanProgress,
  Terminal,
  FindingsPanel,
} from '@/components';
import type { Scan } from '@/types';

// ============================================
// Dashboard Page
// ============================================

export const DashboardPage: React.FC = () => {
  const { stats, recentScans, availableTools, isLoading, error, refresh } = useDashboardData();
  const { currentScan, isScanning } = useScanStore();
  
  // Initialize WebSocket connection
  useWebSocket();
  
  // Subscribe to scan events if there's an active scan
  useScanEvents(currentScan?.scan_id);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <Spinner size="lg" />
          <p className="text-gray-400 mt-4">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Card variant="default" padding="lg" className="max-w-md text-center">
          <AlertTriangle className="w-12 h-12 text-neon-orange mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Failed to load dashboard</h2>
          <p className="text-gray-400 mb-4">{error}</p>
          <Button variant="outline" onClick={refresh}>
            Try Again
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Welcome Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row md:items-center md:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-white display-text mb-2">
            Command Center
          </h1>
          <p className="text-gray-400">
            AI-powered autonomous penetration testing at your fingertips
          </p>
        </div>

        <Link to="/scan">
          <Button variant="cyber" size="lg">
            <Target className="w-5 h-5" />
            Start New Scan
            <ArrowRight className="w-5 h-5" />
          </Button>
        </Link>
      </motion.div>

      {/* Stats Grid */}
      <StatsGrid
        stats={{
          activeScans: stats?.active_scans || 0,
          totalFindings: stats?.total_findings || 0,
          criticalFindings: stats?.critical_findings || 0,
          toolsAvailable: stats?.tools_available || availableTools.length,
        }}
      />

      {/* Active Scan Section */}
      {isScanning && currentScan && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <Card variant="gradient" padding="none" className="overflow-hidden">
            <div className="p-4 bg-neon-green/5 border-b border-neon-green/20">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
                <span className="text-neon-green font-medium">Active Scan</span>
              </div>
            </div>
            <div className="p-6">
              <ScanProgress scan={currentScan} />
            </div>
          </Card>
        </motion.div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Terminal & Findings */}
        <div className="lg:col-span-2 space-y-6">
          {/* Terminal */}
          {isScanning && (
            <Card variant="default" padding="none">
              <Terminal maxHeight="300px" />
            </Card>
          )}

          {/* Recent Findings */}
          {currentScan && currentScan.findings.length > 0 ? (
            <FindingsPanel
              findings={currentScan.findings.slice(0, 5)}
              title="Latest Findings"
              showFilters={false}
              maxHeight="400px"
            />
          ) : (
            <Card variant="default" padding="lg">
              <div className="flex items-center gap-3 mb-4">
                <Shield className="w-5 h-5 text-neon-green" />
                <h3 className="text-lg font-semibold text-white">Recent Findings</h3>
              </div>
              <div className="text-center py-8">
                <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400 mb-2">No recent findings</p>
                <p className="text-sm text-gray-600">
                  Start a scan to discover vulnerabilities
                </p>
              </div>
            </Card>
          )}
        </div>

        {/* Right Column - Stats & Quick Actions */}
        <div className="space-y-6">
          {/* Severity Distribution */}
          {stats && (
            <SeverityDistribution
              critical={stats.critical_findings}
              high={stats.high_findings}
              medium={stats.medium_findings}
              low={stats.low_findings}
              info={0}
            />
          )}

          {/* Recent Scans */}
          <Card variant="default" padding="md">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">Recent Scans</h3>
              <Link to="/reports" className="text-sm text-neon-cyan hover:underline">
                View All
              </Link>
            </div>

            {recentScans.length === 0 ? (
              <div className="text-center py-6">
                <Clock className="w-10 h-10 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-500 text-sm">No scan history</p>
              </div>
            ) : (
              <div className="space-y-3">
                {recentScans.slice(0, 4).map((scan) => (
                  <RecentScanItem key={scan.scan_id} scan={scan} />
                ))}
              </div>
            )}
          </Card>

          {/* Quick Actions */}
          <Card variant="default" padding="md">
            <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
            <div className="space-y-2">
              <QuickAction
                icon={Target}
                label="Quick Scan"
                description="Fast vulnerability scan"
                color="#00ff9d"
                to="/scan?mode=quick"
              />
              <QuickAction
                icon={Zap}
                label="Full Pentest"
                description="Comprehensive assessment"
                color="#ff6600"
                to="/scan?mode=full"
              />
              <QuickAction
                icon={TrendingUp}
                label="View Reports"
                description="Analyze past scans"
                color="#00d4ff"
                to="/reports"
              />
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

// ============================================
// Recent Scan Item Component
// ============================================

interface RecentScanItemProps {
  scan: Scan;
}

const RecentScanItem: React.FC<RecentScanItemProps> = ({ scan }) => {
  const counts = countBySeverity(scan.findings);
  
  const statusColors = {
    running: 'text-neon-green',
    completed: 'text-neon-cyan',
    stopped: 'text-gray-400',
    error: 'text-neon-red',
    paused: 'text-neon-orange',
    initializing: 'text-neon-purple',
  };

  return (
    <Link
      to={`/report/${scan.scan_id}`}
      className="block p-3 rounded-lg bg-cyber-dark/50 hover:bg-cyber-light/30 transition-colors"
    >
      <div className="flex items-start justify-between mb-2">
        <div className="min-w-0 flex-1">
          <p className="text-white font-medium truncate">{scan.target}</p>
          <p className="text-xs text-gray-500">{formatDate(scan.start_time)}</p>
        </div>
        <Badge
          variant={scan.status === 'completed' ? 'success' : scan.status === 'error' ? 'danger' : 'info'}
          size="sm"
        >
          {scan.status}
        </Badge>
      </div>
      
      <div className="flex items-center gap-3 text-xs">
        <span className="text-gray-500">
          {formatDuration(scan.time_elapsed)}
        </span>
        {counts.critical > 0 && (
          <span className="text-[#ff0055]">{counts.critical} critical</span>
        )}
        {counts.high > 0 && (
          <span className="text-[#ff6600]">{counts.high} high</span>
        )}
        <span className="text-gray-400">{scan.findings.length} total</span>
      </div>
    </Link>
  );
};

// ============================================
// Quick Action Component
// ============================================

interface QuickActionProps {
  icon: React.FC<{ className?: string }>;
  label: string;
  description: string;
  color: string;
  to: string;
}

const QuickAction: React.FC<QuickActionProps> = ({
  icon: Icon,
  label,
  description,
  color,
  to,
}) => {
  return (
    <Link
      to={to}
      className="flex items-center gap-3 p-3 rounded-lg bg-cyber-dark/50 hover:bg-cyber-light/30 transition-colors group"
    >
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center transition-transform group-hover:scale-110"
        style={{ backgroundColor: `${color}20` }}
      >
        <Icon className="w-5 h-5" style={{ color }} />
      </div>
      <div className="flex-1">
        <p className="text-white font-medium">{label}</p>
        <p className="text-xs text-gray-500">{description}</p>
      </div>
      <ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-white group-hover:translate-x-1 transition-all" />
    </Link>
  );
};

export default DashboardPage;
