import React from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  AlertTriangle,
  Shield,
  Wrench,
  TrendingUp,
  TrendingDown,
  Minus,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Card } from '@/components/ui';

// ============================================
// Stat Card Component
// ============================================

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.FC<{ className?: string }>;
  color: string;
  trend?: {
    value: number;
    direction: 'up' | 'down' | 'neutral';
  };
  className?: string;
  delay?: number;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  className,
  delay = 0,
}) => {
  const trendIcons = {
    up: TrendingUp,
    down: TrendingDown,
    neutral: Minus,
  };

  const trendColors = {
    up: 'text-neon-green',
    down: 'text-neon-red',
    neutral: 'text-gray-500',
  };

  const TrendIcon = trend ? trendIcons[trend.direction] : null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
    >
      <Card
        variant="default"
        className={cn(
          'relative overflow-hidden group hover:border-opacity-50 transition-all duration-300 p-4',
          className
        )}
      >
        {/* Background Glow */}
        <div
          className="absolute top-0 right-0 w-32 h-32 rounded-full blur-3xl opacity-10 group-hover:opacity-20 transition-opacity"

        />

        <div className="relative z-10">
          <div className="flex items-start justify-between mb-4">
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center"
            >
              <Icon className="w-5 h-5" />
            </div>

            {trend && TrendIcon && (
              <div className={cn('flex items-center gap-1', trendColors[trend.direction])}>
                <TrendIcon className="w-4 h-4" />
                <span className="text-sm font-medium">{trend.value}%</span>
              </div>
            )}
          </div>

          <div>
            <h3 className="text-2xl font-bold text-white mb-1">{value}</h3>
            <p className="text-sm text-gray-400">{title}</p>
            {subtitle && (
              <p className="text-xs text-gray-600 mt-1">{subtitle}</p>
            )}
          </div>
        </div>

        {/* Animated border */}
        <div
          className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"

        />
      </Card>
    </motion.div>
  );
};

// ============================================
// Stats Grid Component
// ============================================

interface StatsGridProps {
  stats: {
    activeScans: number;
    totalFindings: number;
    criticalFindings: number;
    toolsAvailable: number;
    avgScanTime?: number;
    successRate?: number;
  };
  className?: string;
}

export const StatsGrid: React.FC<StatsGridProps> = ({ stats, className }) => {
  return (
    <div className={cn('grid grid-cols-2 md:grid-cols-4 gap-4', className)}>
      <StatCard
        title="Active Scans"
        value={stats.activeScans}
        icon={Activity}
        color="#00ff9d"
        subtitle="Currently running"
        delay={0}
      />

      <StatCard
        title="Total Findings"
        value={stats.totalFindings}
        icon={Shield}
        color="#00d4ff"
        trend={
          stats.totalFindings > 0
            ? { value: 12, direction: 'up' }
            : undefined
        }
        delay={0.1}
      />

      <StatCard
        title="Critical Issues"
        value={stats.criticalFindings}
        icon={AlertTriangle}
        color="#ff0055"
        subtitle="Require immediate action"
        delay={0.2}
      />

      <StatCard
        title="Tools Available"
        value={stats.toolsAvailable}
        icon={Wrench}
        color="#9d00ff"
        delay={0.3}
      />
    </div>
  );
};

// ============================================
// Severity Distribution Card
// ============================================

interface SeverityDistributionProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  className?: string;
}

export const SeverityDistribution: React.FC<SeverityDistributionProps> = ({
  critical,
  high,
  medium,
  low,
  info,
  className,
}) => {
  const total = critical + high + medium + low + info;
  
  const items = [
    { label: 'Critical', value: critical, color: '#ff0055', percentage: (critical / total) * 100 || 0 },
    { label: 'High', value: high, color: '#ff6600', percentage: (high / total) * 100 || 0 },
    { label: 'Medium', value: medium, color: '#ffcc00', percentage: (medium / total) * 100 || 0 },
    { label: 'Low', value: low, color: '#00d4ff', percentage: (low / total) * 100 || 0 },
    { label: 'Info', value: info, color: '#a0a0b0', percentage: (info / total) * 100 || 0 },
  ];

  return (
    <Card variant="default" className={cn('p-4', className)}>
      <h3 className="text-lg font-semibold text-white mb-4">
        Severity Distribution
      </h3>

      {total === 0 ? (
        <div className="text-center py-8">
          <Shield className="w-12 h-12 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-500">No findings yet</p>
        </div>
      ) : (
        <>
          {/* Stacked Bar */}
          <div className="h-4 rounded-full overflow-hidden flex mb-4">
            {items.map((item, idx) => (
              item.percentage > 0 && (
                <motion.div
                  key={item.label}
                  initial={{ width: 0 }}
                  animate={{ width: `${item.percentage}%` }}
                  transition={{ duration: 0.5, delay: idx * 0.1 }}
                  className="h-full"
                />
              )
            ))}
          </div>

          {/* Legend */}
          <div className="grid grid-cols-5 gap-2">
            {items.map((item) => (
              <div key={item.label} className="text-center">
                <div
                  className="w-3 h-3 rounded-full mx-auto mb-1"
                />
                <p className="text-lg font-semibold text-white">{item.value}</p>
                <p className="text-[10px] text-gray-500">{item.label}</p>
              </div>
            ))}
          </div>
        </>
      )}
    </Card>
  );
};

// ============================================
// Mini Stat Component
// ============================================

interface MiniStatProps {
  label: string;
  value: string | number;
  icon: React.FC<{ className?: string }>;
  color?: string;
}

export const MiniStat: React.FC<MiniStatProps> = ({
  label,
  value,
  icon: Icon,
  color = '#00ff9d',
}) => {
  return (
    <div className="flex items-center gap-3 p-3 rounded-lg bg-cyber-dark/50">
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center"
        style={{ backgroundColor: `${color}15` }}
      >
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className="text-white font-medium">{value}</p>
        <p className="text-xs text-gray-500">{label}</p>
      </div>
    </div>
  );
};

// ============================================
// System Health Card
// ============================================

interface SystemHealthProps {
  status: 'healthy' | 'degraded' | 'unhealthy';
  cpuUsage: number;
  memoryUsage: number;
  activeConnections: number;
  className?: string;
}

export const SystemHealth: React.FC<SystemHealthProps> = ({
  status,
  cpuUsage,
  memoryUsage,
  activeConnections,
  className,
}) => {
  const statusConfig = {
    healthy: { color: '#00ff9d', label: 'Healthy' },
    degraded: { color: '#ffcc00', label: 'Degraded' },
    unhealthy: { color: '#ff0055', label: 'Unhealthy' },
  };

  const config = statusConfig[status];

  return (
    <Card variant="default" className={cn('p-4', className)}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white">System Health</h3>
        <div className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: config.color }}
          />
          <span className="text-sm font-medium">
            {config.label}
          </span>
        </div>
      </div>

      <div className="space-y-4">
        <HealthMetric label="CPU Usage" value={cpuUsage} color="#00d4ff" />
        <HealthMetric label="Memory" value={memoryUsage} color="#9d00ff" />
        
        <div className="flex items-center justify-between pt-2 border-t border-cyber-light/20">
          <span className="text-sm text-gray-400">Active Connections</span>
          <span className="text-white font-medium">{activeConnections}</span>
        </div>
      </div>
    </Card>
  );
};

interface HealthMetricProps {
  label: string;
  value: number;
  color: string;
}

const HealthMetric: React.FC<HealthMetricProps> = ({ label, value }) => {
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm text-gray-400">{label}</span>
        <span className="text-sm text-white">{value}%</span>
      </div>
      <div className="h-2 bg-cyber-medium rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 0.5 }}
          className="h-full rounded-full"

        />
      </div>
    </div>
  );
};

export default StatsGrid;
