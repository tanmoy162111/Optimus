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
import { cn } from '@/lib/utils';
import { useSocket, useScanSocket } from '@/hooks';
import { useScanStore } from '@/stores';
import { api } from '@/services';
import {
  Card,
  Button,
  Input,
  Badge,
  ScanProgress,
  Terminal,
  FindingsPanel,
  ToolsPanel,
} from '@/components';// ============================================
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

  const { currentScan, isScanning, setCurrentScan, setIsScanning } = useScanStore();
  const [isStarting, setIsStarting] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  
  // Initialize WebSocket
  useSocket();
  
  // Subscribe to scan events
  useScanSocket(currentScan?.scan_id || null);



  // Validate target - only basic UI validation, backend handles security validation
  const validateTarget = (value: string) => {
    if (!value.trim()) {
      setTargetError('Target is required');
      return false;
    }
  
    setTargetError('');
    return true;
  };

  // Handle scan start - CALLS THE ACTUAL API
  const handleStartScan = async () => {
    if (!validateTarget(target)) return;

    try {
      setIsStarting(true);
      setApiError(null);
      
      // ACTUALLY CALL THE BACKEND API
      const scanResponse = await api.scan.start(target, {
        mode: scanOptions.mode,
        enableExploitation: scanOptions.enableExploitation,
        useAI: scanOptions.useAI,
        maxDuration: scanOptions.maxDuration,
        excludePaths: scanOptions.excludePaths,
      });
      
      // Update state with the response from the backend
      const newScan = {
        scan_id: scanResponse.scan_id,
        target: scanResponse.target,
        status: scanResponse.status as 'initializing' | 'running' | 'paused' | 'completed' | 'error',
        phase: (scanResponse.phase || 'reconnaissance') as 'reconnaissance' | 'scanning' | 'exploitation' | 'post_exploitation' | 'reporting',
        start_time: scanResponse.start_time,
        time_elapsed: scanResponse.time_elapsed || 0,
        coverage: scanResponse.coverage || 0,
        risk_score: scanResponse.risk_score || 0,
        tools_executed: scanResponse.tools_executed || [],
        findings: scanResponse.findings || [],
        options: scanOptions
      };
      
      setCurrentScan(newScan);
      setIsScanning(true);
      
      console.log('[Scan] Started scan:', newScan.scan_id);
      
    } catch (error: any) {
      console.error('Failed to start scan:', error);
      setApiError(error?.response?.data?.error || error?.message || 'Failed to start scan');
      setIsScanning(false);
    } finally {
      setIsStarting(false);
    }
  };

  // Poll for scan status updates
  useEffect(() => {
    if (!currentScan?.scan_id || !isScanning) return;

    const pollInterval = setInterval(async () => {
      try {
        const status = await api.scan.getStatus(currentScan.scan_id);
        if (status) {
          setCurrentScan({
            ...currentScan,
            ...status,
            status: status.status as any,
            phase: status.phase as any,
          });

          if (status.status === 'completed' || status.status === 'error') {
            setIsScanning(false);
          }
        }
      } catch (err) {
        console.error('Failed to poll scan status:', err);
      }
    }, 2000);

    return () => clearInterval(pollInterval);
  }, [currentScan?.scan_id, isScanning]);
  // Handle stop
  const handleStopScan = async () => {
    // Simulate stopping a scan
    setIsScanning(false);
    setCurrentScan(null);
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
            <Card variant="gradient" className="p-6">
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
                    Target ready for backend validation
                  </div>
                )}
              </div>
            </Card>

            {apiError && (
              <Card variant="default" className="p-4 border-red-500/50 bg-red-500/10">
                <div className="flex items-center gap-3 text-red-400">
                  <AlertCircle className="w-5 h-5" />
                  <div>
                    <p className="font-medium">Scan Error</p>
                    <p className="text-sm text-red-300">{apiError}</p>
                  </div>
                </div>
              </Card>
            )}

            {/* Scan Mode */}
            <Card variant="default" className="p-6">
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
            <Card variant="default" className="p-4">
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
              variant="primary"
              size="lg"
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
            <Card variant="default" className="p-4 h-[500px]">
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
            <Card variant="default" className="p-4">
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
                    <Button variant="secondary" size="sm" onClick={() => console.log('Pause clicked')}>
                      <Pause className="w-4 h-4" />
                      Pause
                    </Button>
                  ) : currentScan?.status === 'paused' ? (
                    <Button variant="primary" size="sm" onClick={() => console.log('Resume clicked')}>
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
            <Card variant="default" className="p-0">
              <Terminal maxHeight="400px" />
            </Card>
          </div>

          {/* Findings Sidebar */}
          <div>
            <Card variant="default" className="p-4 h-[600px]">
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
        <div className="w-5 h-5" style={{ color }}>
          <Icon className="w-full h-full" />
        </div>
      </div>
      <h4 className="text-white font-medium mb-1">{title}</h4>
      <p className="text-xs text-gray-500">{description}</p>
    </button>
  );
};

export default ScanPage;
