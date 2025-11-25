import { useEffect, useRef, useState } from 'react';
import { io, Socket } from 'socket.io-client';

const WS_URL = import.meta.env.VITE_WS_URL || 'http://localhost:5000';

export const useWebSocket = () => {
  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    socketRef.current = io(WS_URL);

    socketRef.current.on('connect', () => {
      console.log('WebSocket connected');
      setIsConnected(true);
    });

    socketRef.current.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
    });

    socketRef.current.on('connected', (data) => {
      console.log('Server message:', data.message);
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
