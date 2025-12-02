import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Target,
  Play,
  Pause,
  Square,
  Settings,
  Zap,
  Clock,
  Shield,
  Globe,
  Lock,
  ChevronDown,
  ChevronUp,
  AlertCircle,
} from 'lucide-react';
import { cn, isValidUrl, extractHost } from '@/lib/utils';
import { useScanManager, useScanEvents, useWebSocket } from '@/hooks';
import { useScanStore } from '@/stores';
import {
  Card,
  Button,
  Input,
  Badge,
  Progress,
  ScanProgress,
  Terminal,
  FindingsPanel,
  ToolsPanel,
} from '@/components';

// ============================================
// Scan Page
// ============================================

export const ScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const mode = searchParams.get('mode') || 'standard';

  const [target, setTarget] = useState('');
  const [targetError, setTargetError] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [scanOptions, setScanOptions] = useState({
    mode: mode,
    enableExploitation: false,
    useAI: true,
    maxDuration: 3600,
    excludePaths: '',
  });

  const { currentScan, isStarting, startScan, stopScan, pauseScan, resumeScan } = useScanManager();
  const { isScanning, terminalLines } = useScanStore();

  // Initialize WebSocket
  useWebSocket();

  // Subscribe to scan events
  useScanEvents(currentScan?.scan_id);

  // Validate target
  const validateTarget = (value: string) => {
    if (!value.trim()) {
      setTargetError('Target is required');
      return false;
    }

    // Check if it's a valid URL or IP
    const urlPattern = /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/;
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

    if (!urlPattern.test(value) && !ipPattern.test(value)) {
      setTargetError('Please enter a valid URL or IP address');
      return false;
    }

    setTargetError('');
    return true;
  };

  // Handle scan start
  const handleStartScan = async () => {
    if (!validateTarget(target)) return;

    try {
      const scan = await startScan(target, scanOptions);
      // Navigation is handled by the scan manager
    } catch (error) {
      console.error('Failed to start scan:', error);
    }
  };

  // Handle stop
  const handleStopScan = async () => {
    await stopScan();
    navigate('/');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-2xl md:text-3xl font-bold text-white display-text mb-2">
          {isScanning ? 'Scan in Progress' : 'New Scan'}
        </h1>
        <p className="text-gray-400">
          {isScanning
            ? `Scanning ${currentScan?.target}`
            : 'Configure and launch a new penetration test'}
        </p>
      </motion.div>

      {!isScanning ? (
        /* Scan Configuration */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Config */}
          <div className="lg:col-span-2 space-y-6">
            {/* Target Input */}
            <Card variant="gradient" padding="lg">
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-lg bg-neon-green/20 flex items-center justify-center">
                  <Target className="w-5 h-5 text-neon-green" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-white">Target</h2>
                  <p className="text-sm text-gray-400">
                    Enter the URL or IP address to scan
                  </p>
                </div>
              </div>

              <div className="space-y-4">
                <Input
                  placeholder="https://example.com or 192.168.1.1"
                  value={target}
                  onChange={(e) => {
                    setTarget(e.target.value);
                    if (targetError) validateTarget(e.target.value);
                  }}
                  onBlur={() => validateTarget(target)}
                  error={targetError}
                  icon={<Globe className="w-4 h-4" />}
                  className="text-lg"
                />

                {target && !targetError && (
                  <div className="flex items-center gap-2 text-sm text-gray-400">
                    <Shield className="w-4 h-4 text-neon-green" />
                    Target validated: {extractHost(target)}
                  </div>
                )}
              </div>
            </Card>

            {/* Scan Mode */}
            <Card variant="default" padding="lg">
              <h3 className="text-lg font-semibold text-white mb-4">Scan Mode</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <ScanModeOption
                  id="quick"
                  title="Quick Scan"
                  description="Fast reconnaissance and basic vuln scan"
                  icon={Zap}
                  color="#00ff9d"
                  selected={scanOptions.mode === 'quick'}
                  onSelect={() => setScanOptions({ ...scanOptions, mode: 'quick' })}
                />
                <ScanModeOption
                  id="standard"
                  title="Standard"
                  description="Balanced scan with comprehensive coverage"
                  icon={Target}
                  color="#00d4ff"
                  selected={scanOptions.mode === 'standard'}
                  onSelect={() => setScanOptions({ ...scanOptions, mode: 'standard' })}
                />
                <ScanModeOption
                  id="full"
                  title="Full Pentest"
                  description="Deep analysis with exploitation attempts"
                  icon={Lock}
                  color="#ff6600"
                  selected={scanOptions.mode === 'full'}
                  onSelect={() => setScanOptions({ ...scanOptions, mode: 'full' })}
                />
              </div>
            </Card>

            {/* Advanced Options */}
            <Card variant="default" padding="md">
              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="w-full flex items-center justify-between text-gray-400 hover:text-white transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Settings className="w-4 h-4" />
                  <span>Advanced Options</span>
                </div>
                {showAdvanced ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>

              {showAdvanced && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  className="mt-4 pt-4 border-t border-cyber-light/20 space-y-4"
                >
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <label className="flex items-center gap-3 p-3 rounded-lg bg-cyber-dark/50 cursor-pointer hover:bg-cyber-light/30 transition-colors">
                      <input
                        type="checkbox"
                        checked={scanOptions.enableExploitation}
                        onChange={(e) =>
                          setScanOptions({
                            ...scanOptions,
                            enableExploitation: e.target.checked,
                          })
                        }
                        className="w-4 h-4 accent-neon-green"
                      />
                      <div>
                        <p className="text-white text-sm">Enable Exploitation</p>
                        <p className="text-xs text-gray-500">
                          Attempt to exploit discovered vulnerabilities
                        </p>
                      </div>
                    </label>

                    <label className="flex items-center gap-3 p-3 rounded-lg bg-cyber-dark/50 cursor-pointer hover:bg-cyber-light/30 transition-colors">
                      <input
                        type="checkbox"
                        checked={scanOptions.useAI}
                        onChange={(e) =>
                          setScanOptions({
                            ...scanOptions,
                            useAI: e.target.checked,
                          })
                        }
                        className="w-4 h-4 accent-neon-green"
                      />
                      <div>
                        <p className="text-white text-sm">AI-Powered Analysis</p>
                        <p className="text-xs text-gray-500">
                          Use ML models for intelligent scanning
                        </p>
                      </div>
                    </label>
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-2">
                      Max Duration (seconds)
                    </label>
                    <Input
                      type="number"
                      value={scanOptions.maxDuration}
                      onChange={(e) =>
                        setScanOptions({
                          ...scanOptions,
                          maxDuration: parseInt(e.target.value) || 3600,
                        })
                      }
                      icon={<Clock className="w-4 h-4" />}
                    />
                  </div>

                  <div>
                    <label className="block text-sm text-gray-400 mb-2">
                      Exclude Paths (comma-separated)
                    </label>
                    <Input
                      placeholder="/admin, /logout, /api/internal"
                      value={scanOptions.excludePaths}
                      onChange={(e) =>
                        setScanOptions({
                          ...scanOptions,
                          excludePaths: e.target.value,
                        })
                      }
                    />
                  </div>
                </motion.div>
              )}
            </Card>

            {/* Start Button */}
            <Button
              variant="cyber"
              size="xl"
              className="w-full"
              onClick={handleStartScan}
              isLoading={isStarting}
              disabled={!target || !!targetError}
            >
              <Play className="w-5 h-5" />
              Start Scan
            </Button>
          </div>

          {/* Right Sidebar - Tool Selection */}
          <div className="space-y-6">
            <Card variant="default" padding="md" className="h-[500px]">
              <ToolsPanel target={target} />
            </Card>
          </div>
        </div>
      ) : (
        /* Active Scan View */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-6">
            {/* Progress */}
            {currentScan && <ScanProgress scan={currentScan} />}

            {/* Controls */}
            <Card variant="default" padding="md">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Badge variant="success" size="md">
                    <span className="w-2 h-2 bg-current rounded-full animate-pulse mr-1" />
                    Scanning
                  </Badge>
                  <span className="text-gray-400 text-sm">
                    {currentScan?.tools_executed.length || 0} tools executed
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {currentScan?.status === 'running' ? (
                    <Button variant="warning" size="sm" onClick={pauseScan}>
                      <Pause className="w-4 h-4" />
                      Pause
                    </Button>
                  ) : currentScan?.status === 'paused' ? (
                    <Button variant="primary" size="sm" onClick={resumeScan}>
                      <Play className="w-4 h-4" />
                      Resume
                    </Button>
                  ) : null}
                  <Button variant="danger" size="sm" onClick={handleStopScan}>
                    <Square className="w-4 h-4" />
                    Stop
                  </Button>
                </div>
              </div>
            </Card>

            {/* Terminal */}
            <Card variant="default" padding="none">
              <Terminal maxHeight="400px" />
            </Card>
          </div>

          {/* Findings Sidebar */}
          <div>
            <Card variant="default" padding="md" className="h-[600px]">
              <FindingsPanel
                findings={currentScan?.findings || []}
                showFilters={false}
                maxHeight="520px"
              />
            </Card>
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================
// Scan Mode Option Component
// ============================================

interface ScanModeOptionProps {
  id: string;
  title: string;
  description: string;
  icon: React.FC<{ className?: string }>;
  color: string;
  selected: boolean;
  onSelect: () => void;
}

const ScanModeOption: React.FC<ScanModeOptionProps> = ({
  id,
  title,
  description,
  icon: Icon,
  color,
  selected,
  onSelect,
}) => {
  return (
    <button
      onClick={onSelect}
      className={cn(
        'p-4 rounded-lg border-2 transition-all duration-200 text-left',
        selected
          ? 'border-opacity-100 bg-opacity-10'
          : 'border-cyber-light/30 hover:border-opacity-50 bg-cyber-dark/50'
      )}
      style={{
        borderColor: selected ? color : undefined,
        backgroundColor: selected ? `${color}10` : undefined,
      }}
    >
      <div
        className="w-10 h-10 rounded-lg flex items-center justify-center mb-3"
        style={{ backgroundColor: `${color}20` }}
      >
        <Icon className="w-5 h-5" style={{ color }} />
      </div>
      <h4 className="text-white font-medium mb-1">{title}</h4>
      <p className="text-xs text-gray-500">{description}</p>
    </button>
  );
};

export default ScanPage;
