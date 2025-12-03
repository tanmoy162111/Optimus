import { io, Socket } from 'socket.io-client';
import { config } from '@/config';
import type { 
  ScanStartedEvent, 
  PhaseTransitionEvent, 
  ToolOutputEvent, 
  ToolExecutionEvent,
  ScanUpdateEvent,
  FindingEvent
} from '@/types';

// ============================================
// WebSocket Service (Singleton)
// ============================================

type EventCallback<T = unknown> = (data: T) => void;

interface SocketEvents {
  // Connection events
  connect: () => void;
  disconnect: (reason: string) => void;
  connect_error: (error: Error) => void;
  
  // Scan events
  scan_started: EventCallback<ScanStartedEvent>;
  scan_complete: EventCallback<{ 
    scan_id: string; 
    findings_count: number; 
    time_elapsed: number 
  }>;
  scan_error: EventCallback<{ scan_id: string; error: string }>;
  scan_update: EventCallback<ScanUpdateEvent>;
  
  // Phase events
  phase_transition: EventCallback<PhaseTransitionEvent>;
  
  // Tool events
  tool_recommendation: EventCallback<{ tool: string; phase: string; confidence: number }>;
  tool_execution_start: EventCallback<ToolExecutionEvent>;
  tool_execution_complete: EventCallback<ToolExecutionEvent>;
  tool_output: EventCallback<ToolOutputEvent>;
  tool_error_output: EventCallback<{ tool: string; error: string }>;
  
  // Finding events
  finding_discovered: EventCallback<FindingEvent>;
  
  // Tool resolution events (Hybrid System)
  tool_resolution: EventCallback<{
    tool: string;
    source: string;
    confidence: number;
    status: string;
    explanation: string;
  }>;
  tool_executing: EventCallback<{ tool: string; command: string; source: string }>;
  tool_blocked: EventCallback<{ tool: string; command: string; reason: string }>;
  tool_warning: EventCallback<{ tool: string; message: string; warnings: string[] }>;
  tool_fallback: EventCallback<{ original: string; alternative: string }>;
  
  // System events
  system_status: EventCallback<{ status: string; message: string }>;
}

class SocketService {
  private static instance: SocketService;
  private socket: Socket | null = null;
  private listeners: Map<string, Set<EventCallback>> = new Map();
  private reconnectAttempts = 0;
  private isConnecting = false;
  
  private constructor() {}
  
  static getInstance(): SocketService {
    if (!SocketService.instance) {
      SocketService.instance = new SocketService();
    }
    return SocketService.instance;
  }
  
  /**
   * Connect to WebSocket server
   */
  connect(): Socket {
    if (this.socket?.connected) {
      return this.socket;
    }
    
    if (this.isConnecting) {
      return this.socket!;
    }
    
    this.isConnecting = true;
    
    this.socket = io(config.wsUrl, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: config.reconnectAttempts,
      reconnectionDelay: config.reconnectDelay,
      timeout: 10000,
    });
    
    this.setupDefaultListeners();
    this.isConnecting = false;
    
    return this.socket;
  }
  
  /**
   * Disconnect from WebSocket server
   */
  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.listeners.clear();
    this.reconnectAttempts = 0;
  }
  
  /**
   * Get connection status
   */
  isConnected(): boolean {
    return this.socket?.connected ?? false;
  }
  
  /**
   * Get socket instance
   */
  getSocket(): Socket | null {
    return this.socket;
  }
  
  /**
   * Setup default event listeners
   */
  private setupDefaultListeners(): void {
    if (!this.socket) return;
    
    this.socket.on('connect', () => {
      console.log('[WS] Connected to server');
      this.reconnectAttempts = 0;
    });
    
    this.socket.on('disconnect', (reason) => {
      console.log('[WS] Disconnected:', reason);
    });
    
    this.socket.on('connect_error', (error) => {
      console.error('[WS] Connection error:', error.message);
      this.reconnectAttempts++;
    });
    
    // Re-attach all stored listeners
    this.listeners.forEach((callbacks, event) => {
      callbacks.forEach(callback => {
        this.socket!.on(event, callback as any);
      });
    });
  }
  
  /**
   * Subscribe to an event
   */
  on<K extends keyof SocketEvents>(event: K, callback: SocketEvents[K]): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    
    this.listeners.get(event)!.add(callback as EventCallback);
    
    if (this.socket) {
      this.socket.on(event, callback as any);
    }
    
    // Return unsubscribe function
    return () => this.off(event, callback);
  }
  
  /**
   * Unsubscribe from an event
   */
  off<K extends keyof SocketEvents>(event: K, callback?: SocketEvents[K]): void {
    if (callback) {
      this.listeners.get(event)?.delete(callback as EventCallback);
      this.socket?.off(event, callback as any);
    } else {
      this.listeners.delete(event);
      this.socket?.off(event);
    }
  }
  
  /**
   * Emit event to server
   */
  emit<T = unknown>(event: string, data?: T): void {
    if (this.socket?.connected) {
      this.socket.emit(event, data);
    } else {
      console.warn('[WS] Cannot emit, socket not connected');
    }
  }
  
  /**
   * Join a scan room for real-time updates
   */
  joinScan(scanId: string): void {
    this.emit('join_scan', { scan_id: scanId });
    console.log('[WS] Joined scan room:', scanId);
  }
  
  /**
   * Leave a scan room
   */
  leaveScan(scanId: string): void {
    this.emit('leave_scan', { scan_id: scanId });
    console.log('[WS] Left scan room:', scanId);
  }
  
  /**
   * Send command to execute tool
   */
  executeTool(scanId: string, tool: string, target: string, options?: Record<string, unknown>): void {
    this.emit('execute_tool', { scan_id: scanId, tool, target, options });
  }
  
  /**
   * Request tool recommendation
   */
  requestToolRecommendation(scanId: string, phase: string, context?: Record<string, unknown>): void {
    this.emit('request_tool_recommendation', { scan_id: scanId, phase, context });
  }
}

// Export singleton instance
export const socketService = SocketService.getInstance();
export default socketService;