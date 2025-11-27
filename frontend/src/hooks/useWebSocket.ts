import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';
import { useScanStore } from '../store/scanStore';

const WS_URL = import.meta.env.VITE_WS_URL || 'http://localhost:5000';

export const useWebSocket = () => {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const { setCurrentScan, addOutputLine, addFindings, updateScan } = useScanStore();

  useEffect(() => {
    socketRef.current = io(WS_URL, { transports: ['websocket','polling'], reconnection: true });

    socketRef.current.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
    });

    socketRef.current.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
    });

    socketRef.current.on('scan_started', (data) => {
      console.log('🚀 Scan started:', data);
      addOutputLine(`🚀 Scan started for ${data.target}`);
      setCurrentScan({
        scan_id: data.scan_id,
        target: data.target,
        phase: 'reconnaissance',
        status: 'running',
        findings: [],
        tools_executed: [],
        time_elapsed: 0,
        coverage: 0
      } as any);
    });

    socketRef.current.on('phase_transition', (data) => {
      console.log('📍 Phase transition:', data);
      addOutputLine(`\n📍 Phase transition: ${data.from} → ${data.to}`);
      updateScan({ phase: data.to });
    });

    socketRef.current.on('tool_recommendation', (data) => {
      console.log('🔧 Tool recommended:', data);
      addOutputLine(`🔧 Recommended tool for ${data.phase}: ${data.tool}`);
    });

    socketRef.current.on('tool_execution_start', (data) => {
      addOutputLine(`[${data.tool}] starting on ${data.target || ''}`);
    });

    socketRef.current.on('tool_output', (data) => {
      if (data?.output) addOutputLine(data.output);
    });

    socketRef.current.on('tool_error_output', (data) => {
      addOutputLine(`ERROR: ${data?.error}`);
    });

    socketRef.current.on('tool_execution_complete', (data) => {
      addOutputLine(`[${data.tool}] completed in ${data.execution_time ?? ''}s`);
    });

    socketRef.current.on('scan_update', (data) => {
      console.log('📊 Scan update:', data);
      if (Array.isArray(data.findings)) {
        addFindings(data.findings);
      }
      updateScan({ 
        phase: data.phase,
        coverage: data.coverage, 
        time_elapsed: data.time_elapsed,
        tools_executed: data.tools_executed 
      });
    });

    socketRef.current.on('scan_complete', (data) => {
      console.log('✅ Scan complete:', data);
      addOutputLine(`\n✅ Scan complete: ${data.findings_count} findings in ${data.time_elapsed}s`);
      updateScan({ status: 'completed' });
    });

    socketRef.current.on('scan_error', (data) => {
      addOutputLine(`SCAN ERROR: ${data?.error}`);
      updateScan({ status: 'error' });
    });

    return () => {
      socketRef.current?.disconnect();
    };
  }, []);

  const joinScan = (scanId: string) => {
    socketRef.current?.emit('join_scan', { scan_id: scanId });
  };

  const leaveScan = (scanId: string) => {
    socketRef.current?.emit('leave_scan', { scan_id: scanId });
  };

  const on = (event: string, callback: (data: any) => void) => {
    socketRef.current?.on(event, callback);
  };

  const off = (event: string) => {
    socketRef.current?.off(event);
  };

  return {
    socket: socketRef.current,
    isConnected,
    joinScan,
    leaveScan,
    on,
    off
  };
};
