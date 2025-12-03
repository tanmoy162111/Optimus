import React from 'react';
import { motion } from 'framer-motion';
import {
  Search,
  Radar,
  List,
  Zap,
  Key,
  FileText,
  Check,
  Loader2,
  Clock,
  Target,
  Activity,
} from 'lucide-react';
import { cn, formatDuration, getPhaseIndex } from '@/lib/utils';
import { phaseConfig } from '@/config';
import { Card, Badge, Progress } from '@/components/ui';
import type { ScanPhase, ScanStatus, Scan } from '@/types';

// ============================================
// Phase Icon Map
// ============================================

const phaseIcons: Record<ScanPhase, React.FC<{ className?: string }>> = {
  reconnaissance: Search,
  scanning: Radar,
  enumeration: List,
  exploitation: Zap,
  post_exploitation: Key,
  reporting: FileText,
};

// ============================================
// Scan Progress Component
// ============================================

interface ScanProgressProps {
  scan: Scan;
  className?: string;
  compact?: boolean;
}

export const ScanProgress: React.FC<ScanProgressProps> = ({
  scan,
  className,
  compact = false,
}) => {
  const phases: ScanPhase[] = [
    'reconnaissance',
    'scanning',
    'enumeration',
    'exploitation',
    'post_exploitation',
    'reporting',
  ];

  const currentPhaseIndex = getPhaseIndex(scan.phase);
  const progressPercentage = ((currentPhaseIndex + 1) / phases.length) * 100;

  if (compact) {
    return (
      <CompactProgress
        scan={scan}
        phases={phases}
        currentPhaseIndex={currentPhaseIndex}
        className={className}
      />
    );
  }

  return (
    <Card variant="default" className={cn('p-4', className)}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div
              className={cn(
                'w-10 h-10 rounded-lg flex items-center justify-center',
                scan.status === 'running'
                  ? 'bg-neon-green/20'
                  : scan.status === 'completed'
                  ? 'bg-neon-cyan/20'
                  : 'bg-cyber-light'
              )}
            >
              {scan.status === 'running' ? (
                <Loader2 className="w-5 h-5 text-neon-green animate-spin" />
              ) : scan.status === 'completed' ? (
                <Check className="w-5 h-5 text-neon-cyan" />
              ) : (
                <Activity className="w-5 h-5 text-gray-400" />
              )}
            </div>
            {scan.status === 'running' && (
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-neon-green rounded-full animate-pulse" />
            )}
          </div>
          <div>
            <h3 className="text-white font-medium">Scan Progress</h3>
            <p className="text-sm text-gray-500">
              Target: {scan.target}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <StatusBadge status={scan.status} />
          <div className="text-right">
            <p className="text-sm text-gray-400">Elapsed</p>
            <p className="text-white font-mono">
              {formatDuration(scan.time_elapsed)}
            </p>
          </div>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm text-gray-400">Overall Progress</span>
          <span className="text-sm text-neon-green font-mono">
            {progressPercentage.toFixed(0)}%
          </span>
        </div>
        <Progress value={progressPercentage} variant="gradient" size="md" />
      </div>

      {/* Phase Timeline */}
      <div className="relative">
        {/* Connection Line */}
        <div className="absolute top-5 left-5 right-5 h-0.5 bg-cyber-light" />
        <div
          className="absolute top-5 left-5 h-0.5 bg-gradient-to-r from-neon-green to-neon-cyan transition-all duration-500"
          style={{ width: `${Math.max(0, (currentPhaseIndex / (phases.length - 1)) * 100)}%` }}
        />

        {/* Phase Nodes */}
        <div className="relative flex justify-between">
          {phases.map((phase, index) => {
            const Icon = phaseIcons[phase];
            const config = phaseConfig[phase];
            const isActive = index === currentPhaseIndex;
            const isCompleted = index < currentPhaseIndex;
            const isPending = index > currentPhaseIndex;

            return (
              <div
                key={phase}
                className="flex flex-col items-center"
              >
                <motion.div
                  initial={false}
                  animate={{
                    scale: isActive ? 1.1 : 1,
                    opacity: isPending ? 0.5 : 1,
                  }}
                  className={cn(
                    'w-10 h-10 rounded-full flex items-center justify-center relative z-10 transition-all duration-300',
                    isActive && 'ring-2 ring-neon-green ring-offset-2 ring-offset-cyber-dark',
                    isCompleted && 'bg-neon-green/20',
                    isActive && 'bg-neon-green/30',
                    isPending && 'bg-cyber-light'
                  )}
                  style={{
                    borderColor: isCompleted || isActive ? config.color : undefined,
                    borderWidth: isCompleted || isActive ? 2 : 0,
                  }}
                >
                  {isCompleted ? (
                    <Check className="w-4 h-4 text-neon-green" />
                  ) : isActive && scan.status === 'running' ? (
                    <Loader2
                      className="w-4 h-4 animate-spin"
                      style={{ color: config.color }}
                    />
                  ) : (
                    <Icon
                      className={cn(
                        'w-4 h-4',
                        isPending ? 'text-gray-500' : 'text-white'
                      )}

                    />
                  )}
                </motion.div>

                <div className="mt-2 text-center">
                  <p
                    className={cn(
                      'text-xs font-medium',
                      isActive ? 'text-white' : isPending ? 'text-gray-600' : 'text-gray-400'
                    )}
                  >
                    {config.label}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mt-6 pt-6 border-t border-cyber-light/20">
        <StatItem
          icon={Target}
          label="Coverage"
          value={`${(scan.coverage * 100).toFixed(0)}%`}
          color="#00ff9d"
        />
        <StatItem
          icon={Activity}
          label="Findings"
          value={scan.findings.length.toString()}
          color="#00d4ff"
        />
        <StatItem
          icon={Zap}
          label="Tools Run"
          value={scan.tools_executed.length.toString()}
          color="#9d00ff"
        />
        <StatItem
          icon={Clock}
          label="Phase Time"
          value={formatDuration(scan.time_elapsed / (currentPhaseIndex + 1))}
          color="#ffcc00"
        />
      </div>
    </Card>
  );
};

// ============================================
// Compact Progress Component
// ============================================

interface CompactProgressProps {
  scan: Scan;
  phases: ScanPhase[];
  currentPhaseIndex: number;
  className?: string;
}

const CompactProgress: React.FC<CompactProgressProps> = ({
  scan,
  phases,
  currentPhaseIndex,
  className,
}) => {
  const config = phaseConfig[scan.phase];
  const Icon = phaseIcons[scan.phase];
  const progressPercentage = ((currentPhaseIndex + 1) / phases.length) * 100;

  return (
    <div className={cn('flex items-center gap-4', className)}>
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center"
      >
        {scan.status === 'running' ? (
          <Loader2
            className="w-4 h-4 animate-spin"
          />
        ) : (
          <Icon className="w-4 h-4" />
        )}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-1">
          <span className="text-sm text-white font-medium truncate">
            {config.label}
          </span>
          <span className="text-xs text-gray-500">
            {progressPercentage.toFixed(0)}%
          </span>
        </div>
        <Progress value={progressPercentage} variant="gradient" size="sm" />
      </div>

      <div className="text-right">
        <p className="text-xs text-gray-500">Elapsed</p>
        <p className="text-sm text-white font-mono">
          {formatDuration(scan.time_elapsed)}
        </p>
      </div>
    </div>
  );
};

// ============================================
// Status Badge Component
// ============================================

interface StatusBadgeProps {
  status: ScanStatus;
}

const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const statusConfig: Record<ScanStatus, { variant: 'success' | 'warning' | 'danger' | 'info' | 'default'; label: string }> = {
    initializing: { variant: 'info', label: 'Initializing' },
    running: { variant: 'success', label: 'Running' },
    paused: { variant: 'warning', label: 'Paused' },
    completed: { variant: 'info', label: 'Completed' },
    stopped: { variant: 'default', label: 'Stopped' },
    error: { variant: 'danger', label: 'Error' },
  };

  const config = statusConfig[status];

  return (
    <Badge variant={config.variant} size="md">
      {status === 'running' && (
        <span className="w-2 h-2 bg-current rounded-full animate-pulse mr-1" />
      )}
      {config.label}
    </Badge>
  );
};

// ============================================
// Stat Item Component
// ============================================

interface StatItemProps {
  icon: React.FC<{ className?: string }>;
  label: string;
  value: string;
  color: string;
}

const StatItem: React.FC<StatItemProps> = ({ icon: Icon, label, value }) => {
  return (
    <div className="text-center">
      <div
        className="w-8 h-8 rounded-lg flex items-center justify-center mx-auto mb-2"
      >
        <Icon className="w-4 h-4" />
      </div>
      <p className="text-lg font-semibold text-white">{value}</p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
};

export default ScanProgress;
