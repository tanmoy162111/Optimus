import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import type { 
  Scan, 
  Vulnerability, 
  TerminalLine, 
  Notification,
  DashboardStats,
  Tool,
  ScanPhase,
  ScanStatus 
} from '@/types';
import { generateId } from '@/lib/utils';
import { config } from '@/config';

// ============================================
// Scan Store
// ============================================

interface ScanState {
  // Current scan data
  currentScan: Scan | null;
  scanHistory: Scan[];
  isScanning: boolean;
  
  // Terminal output
  terminalLines: TerminalLine[];
  
  // Actions
  setCurrentScan: (scan: Scan | null) => void;
  updateScan: (updates: Partial<Scan>) => void;
  updatePhase: (phase: ScanPhase) => void;
  updateStatus: (status: ScanStatus) => void;
  addFinding: (finding: Vulnerability) => void;
  addFindings: (findings: Vulnerability[]) => void;
  addToolExecution: (tool: string) => void;
  updateCoverage: (coverage: number) => void;
  setIsScanning: (status: boolean) => void;
  clearCurrentScan: () => void;
  addToHistory: (scan: Scan) => void;
  
  // Terminal actions
  addTerminalLine: (line: Omit<TerminalLine, 'id' | 'timestamp'>) => void;
  clearTerminal: () => void;
}

export const useScanStore = create<ScanState>()(
  devtools(
    (set) => ({
      currentScan: null,
      scanHistory: [],
      isScanning: false,
      terminalLines: [],
      
      setCurrentScan: (scan) => set({ 
        currentScan: scan, 
        isScanning: scan !== null && scan.status === 'running' 
      }),
      
      updateScan: (updates) => set((state) => ({
        currentScan: state.currentScan 
          ? { ...state.currentScan, ...updates }
          : null
      })),
      
      updatePhase: (phase) => set((state) => ({
        currentScan: state.currentScan
          ? { ...state.currentScan, phase }
          : null
      })),
      
      updateStatus: (status) => set((state) => ({
        currentScan: state.currentScan
          ? { ...state.currentScan, status }
          : null,
        isScanning: status === 'running'
      })),
      
      addFinding: (finding) => set((state) => ({
        currentScan: state.currentScan
          ? {
              ...state.currentScan,
              findings: [...state.currentScan.findings, finding]
            }
          : null
      })),
      
      addFindings: (findings) => set((state) => ({
        currentScan: state.currentScan
          ? {
              ...state.currentScan,
              findings: [...state.currentScan.findings, ...findings]
            }
          : null
      })),
      
      addToolExecution: (tool) => set((state) => ({
        currentScan: state.currentScan
          ? {
              ...state.currentScan,
              tools_executed: [
                ...state.currentScan.tools_executed,
                {
                  tool,
                  started_at: new Date().toISOString(),
                  status: 'running' as const,
                  findings_count: 0
                }
              ]
            }
          : null
      })),
      
      updateCoverage: (coverage) => set((state) => ({
        currentScan: state.currentScan
          ? { ...state.currentScan, coverage }
          : null
      })),
      
      setIsScanning: (status) => set({ isScanning: status }),
      
      clearCurrentScan: () => set({ 
        currentScan: null, 
        isScanning: false,
        terminalLines: []
      }),
      
      addToHistory: (scan) => set((state) => ({
        scanHistory: [scan, ...state.scanHistory].slice(0, 50) // Keep last 50
      })),
      
      addTerminalLine: (line) => set((state) => {
        const newLine: TerminalLine = {
          ...line,
          id: generateId(),
          timestamp: new Date().toISOString()
        };
        
        const lines = [...state.terminalLines, newLine];
        // Keep only last N lines
        if (lines.length > config.maxLogLines) {
          return { terminalLines: lines.slice(-config.maxLogLines) };
        }
        return { terminalLines: lines };
      }),
      
      clearTerminal: () => set({ terminalLines: [] }),
    }),
    { name: 'scan-store' }
  )
);

// ============================================
// UI Store
// ============================================

interface UIState {
  // Sidebar
  sidebarOpen: boolean;
  sidebarCollapsed: boolean;
  
  // Theme
  theme: 'dark' | 'light';
  
  // Notifications
  notifications: Notification[];
  
  // Modals
  activeModal: string | null;
  modalData: unknown;
  
  // Actions
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setTheme: (theme: 'dark' | 'light') => void;
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void;
  removeNotification: (id: string) => void;
  markNotificationRead: (id: string) => void;
  clearNotifications: () => void;
  openModal: (modal: string, data?: unknown) => void;
  closeModal: () => void;
}

export const useUIStore = create<UIState>()(
  persist(
    devtools(
      (set) => ({
        sidebarOpen: true,
        sidebarCollapsed: false,
        theme: 'dark',
        notifications: [],
        activeModal: null,
        modalData: null,
        
        toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
        
        setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
        
        setTheme: (theme) => set({ theme }),
        
        addNotification: (notification) => set((state) => ({
          notifications: [
            {
              ...notification,
              id: generateId(),
              timestamp: new Date().toISOString(),
              read: false
            },
            ...state.notifications
          ].slice(0, 50)
        })),
        
        removeNotification: (id) => set((state) => ({
          notifications: state.notifications.filter(n => n.id !== id)
        })),
        
        markNotificationRead: (id) => set((state) => ({
          notifications: state.notifications.map(n =>
            n.id === id ? { ...n, read: true } : n
          )
        })),
        
        clearNotifications: () => set({ notifications: [] }),
        
        openModal: (modal, data) => set({ activeModal: modal, modalData: data }),
        
        closeModal: () => set({ activeModal: null, modalData: null }),
      }),
      { name: 'ui-store' }
    ),
    {
      name: 'optimus-ui-settings',
      partialize: (state) => ({ 
        theme: state.theme, 
        sidebarCollapsed: state.sidebarCollapsed 
      }),
    }
  )
);

// ============================================
// Dashboard Store
// ============================================

interface DashboardState {
  stats: DashboardStats | null;
  recentScans: Scan[];
  availableTools: Tool[];
  isLoading: boolean;
  error: string | null;
  
  // Actions
  setStats: (stats: DashboardStats) => void;
  setRecentScans: (scans: Scan[]) => void;
  setAvailableTools: (tools: Tool[]) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
}

export const useDashboardStore = create<DashboardState>()(
  devtools(
    (set) => ({
      stats: null,
      recentScans: [],
      availableTools: [],
      isLoading: false,
      error: null,
      
      setStats: (stats) => set({ stats }),
      setRecentScans: (scans) => set({ recentScans: scans }),
      setAvailableTools: (tools) => set({ availableTools: tools }),
      setLoading: (loading) => set({ isLoading: loading }),
      setError: (error) => set({ error }),
    }),
    { name: 'dashboard-store' }
  )
);

// ============================================
// Connection Store
// ============================================

interface ConnectionState {
  isConnected: boolean;
  connectionError: string | null;
  reconnectAttempts: number;
  
  // Actions
  setConnected: (connected: boolean) => void;
  setConnectionError: (error: string | null) => void;
  incrementReconnectAttempts: () => void;
  resetReconnectAttempts: () => void;
}

export const useConnectionStore = create<ConnectionState>()(
  devtools(
    (set) => ({
      isConnected: false,
      connectionError: null,
      reconnectAttempts: 0,
      
      setConnected: (connected) => set({ 
        isConnected: connected,
        connectionError: connected ? null : undefined
      }),
      
      setConnectionError: (error) => set({ connectionError: error }),
      
      incrementReconnectAttempts: () => set((state) => ({
        reconnectAttempts: state.reconnectAttempts + 1
      })),
      
      resetReconnectAttempts: () => set({ reconnectAttempts: 0 }),
    }),
    { name: 'connection-store' }
  )
);
