import { useEffect, useCallback, useRef, useState } from 'react';
import { socketService } from '@/services/socket';
import { api } from '@/services/api';
import { 
  useScanStore, 
  useConnectionStore, 
  useDashboardStore,
  useUIStore 
} from '@/stores';
import type { ScanPhase, ToolOutputEvent } from '@/types';

// ============================================
// useSocket Hook - Manages WebSocket Connection
// ============================================

export function useSocket() {
  const { setConnected, setConnectionError, resetReconnectAttempts } = useConnectionStore();
  const isInitialized = useRef(false);
  
  useEffect(() => {
    if (isInitialized.current) return;
    isInitialized.current = true;
    
    socketService.connect();
    
    const unsubConnect = socketService.on('connect', () => {
      setConnected(true);
      setConnectionError(null);
      resetReconnectAttempts();
    });
    
    const unsubDisconnect = socketService.on('disconnect', (reason) => {
      setConnected(false);
      if (reason === 'io server disconnect') {
        setConnectionError('Server disconnected');
      }
    });
    
    const unsubError = socketService.on('connect_error', (error) => {
      setConnected(false);
      setConnectionError(error.message);
    });
    
    return () => {
      unsubConnect();
      unsubDisconnect();
      unsubError();
    };
  }, [setConnected, setConnectionError, resetReconnectAttempts]);
  
  return {
    isConnected: useConnectionStore((s) => s.isConnected),
    connectionError: useConnectionStore((s) => s.connectionError),
    socket: socketService,
  };
}

// ============================================
// useScanSocket Hook - Handles Scan-Specific Events
// ============================================

export function useScanSocket(scanId: string | null) {
  const { 
    updatePhase, 
    updateStatus, 
    addFinding, 
    addTerminalLine,
    updateCoverage,
  } = useScanStore();
  const { addNotification } = useUIStore();
  
  useEffect(() => {
    if (!scanId) return;
    
    // Join scan room
    socketService.joinScan(scanId);
    
    // Phase transition
    const unsubPhase = socketService.on('phase_transition', (data) => {
      updatePhase(data.to as ScanPhase);
      addTerminalLine({
        content: `Phase transition: ${data.from} → ${data.to}`,
        type: 'info',
        tool: 'system'
      });
    });
    
    // Scan updates
    const unsubUpdate = socketService.on('scan_update', (data) => {
      updateStatus(data.status);
      updateCoverage(data.coverage);
      if (data.findings) {
        data.findings.forEach(f => addFinding(f));
      }
    });
    
    // Tool output
    const unsubOutput = socketService.on('tool_output', (data: ToolOutputEvent) => {
      addTerminalLine({
        content: data.output,
        type: data.stream === 'stderr' ? 'error' : 'output',
        tool: data.tool
      });
    });
    
    // Tool execution events
    const unsubToolStart = socketService.on('tool_execution_start', (data) => {
      addTerminalLine({
        content: `Starting ${data.tool}...`,
        type: 'info',
        tool: data.tool
      });
    });
    
    const unsubToolComplete = socketService.on('tool_execution_complete', (data) => {
      addTerminalLine({
        content: `${data.tool} completed (${data.findings_count} findings)`,
        type: data.success ? 'success' : 'warning',
        tool: data.tool
      });
    });
    
    // Findings
    const unsubFinding = socketService.on('finding_discovered', (data) => {
      addFinding(data.finding);
      if (data.finding.severity >= 7) {
        addNotification({
          type: data.finding.severity >= 9 ? 'error' : 'warning',
          title: `${data.finding.severity >= 9 ? 'Critical' : 'High'} Vulnerability Found`,
          message: data.finding.name
        });
      }
    });
    
    // Scan complete
    const unsubComplete = socketService.on('scan_complete', (data) => {
      updateStatus('completed');
      addTerminalLine({
        content: `Scan completed. ${data.findings_count} findings in ${data.time_elapsed.toFixed(1)}s`,
        type: 'success',
        tool: 'system'
      });
      addNotification({
        type: 'success',
        title: 'Scan Complete',
        message: `Found ${data.findings_count} vulnerabilities`
      });
    });
    
    // Scan error
    const unsubError = socketService.on('scan_error', (data) => {
      updateStatus('error');
      addTerminalLine({
        content: `Error: ${data.error}`,
        type: 'error',
        tool: 'system'
      });
      addNotification({
        type: 'error',
        title: 'Scan Error',
        message: data.error
      });
    });
    
    // Tool resolution (Hybrid System)
    const unsubResolution = socketService.on('tool_resolution', (data) => {
      addTerminalLine({
        content: `Tool ${data.tool} resolved via ${data.source} (${(data.confidence * 100).toFixed(0)}% confidence)`,
        type: 'info',
        tool: data.tool
      });
    });
    
    // Tool blocked
    const unsubBlocked = socketService.on('tool_blocked', (data) => {
      addTerminalLine({
        content: `⚠️ Command blocked: ${data.reason}`,
        type: 'warning',
        tool: data.tool
      });
    });
    
    return () => {
      socketService.leaveScan(scanId);
      unsubPhase();
      unsubUpdate();
      unsubOutput();
      unsubToolStart();
      unsubToolComplete();
      unsubFinding();
      unsubComplete();
      unsubError();
      unsubResolution();
      unsubBlocked();
    };
  }, [scanId, updatePhase, updateStatus, addFinding, addTerminalLine, updateCoverage, addNotification]);
}

// ============================================
// useDashboardData Hook - Fetches Dashboard Data
// ============================================

export function useDashboardData() {
  const { 
    setStats, 
    setRecentScans, 
    setAvailableTools, 
    setLoading, 
    setError 
  } = useDashboardStore();
  
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const [stats, scansResult, tools] = await Promise.all([
        api.dashboard.getStats(),
        api.scan.list({ limit: 5 }),
        api.tools.getAvailable()
      ]);
      
      setStats(stats);
      setRecentScans(scansResult.items);
      setAvailableTools(tools);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load dashboard';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, [setStats, setRecentScans, setAvailableTools, setLoading, setError]);
  
  useEffect(() => {
    fetchData();
  }, [fetchData]);
  
  return {
    ...useDashboardStore(),
    refresh: fetchData
  };
}

// ============================================
// useDebounce Hook
// ============================================

export function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState(value);
  
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  
  return debouncedValue;
}

// ============================================
// useInterval Hook
// ============================================

export function useInterval(callback: () => void, delay: number | null) {
  const savedCallback = useRef(callback);
  
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);
  
  useEffect(() => {
    if (delay === null) return;
    
    const id = setInterval(() => savedCallback.current(), delay);
    return () => clearInterval(id);
  }, [delay]);
}

// ============================================
// useLocalStorage Hook
// ============================================

export function useLocalStorage<T>(key: string, initialValue: T) {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch {
      return initialValue;
    }
  });
  
  const setValue = useCallback((value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
    } catch (error) {
      console.error('useLocalStorage error:', error);
    }
  }, [key, storedValue]);
  
  return [storedValue, setValue] as const;
}

// ============================================
// useClickOutside Hook
// ============================================

export function useClickOutside(
  ref: React.RefObject<HTMLElement>,
  handler: () => void
) {
  useEffect(() => {
    const listener = (event: MouseEvent | TouchEvent) => {
      if (!ref.current || ref.current.contains(event.target as Node)) {
        return;
      }
      handler();
    };
    
    document.addEventListener('mousedown', listener);
    document.addEventListener('touchstart', listener);
    
    return () => {
      document.removeEventListener('mousedown', listener);
      document.removeEventListener('touchstart', listener);
    };
  }, [ref, handler]);
}

// ============================================
// useKeyPress Hook
// ============================================

export function useKeyPress(targetKey: string, handler: () => void) {
  useEffect(() => {
    const downHandler = (event: KeyboardEvent) => {
      if (event.key === targetKey) {
        handler();
      }
    };
    
    window.addEventListener('keydown', downHandler);
    return () => window.removeEventListener('keydown', downHandler);
  }, [targetKey, handler]);
}

// ============================================
// useCopyToClipboard Hook
// ============================================

export function useCopyToClipboard() {
  const [copied, setCopied] = useState(false);
  
  const copy = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      return true;
    } catch {
      setCopied(false);
      return false;
    }
  }, []);
  
  return { copied, copy };
}
