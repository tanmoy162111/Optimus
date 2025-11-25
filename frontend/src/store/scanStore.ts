import { create } from 'zustand';
import { ScanState, Vulnerability } from '../types/scan.types';

interface ScanStore {
  currentScan: ScanState | null;
  scanHistory: ScanState[];
  isScanning: boolean;
  
  setCurrentScan: (scan: ScanState | null) => void;
  updateScan: (updates: Partial<ScanState>) => void;
  addFinding: (finding: Vulnerability) => void;
  addFindings: (findings: Vulnerability[]) => void;
  addToHistory: (scan: ScanState) => void;
  setIsScanning: (status: boolean) => void;
  clearCurrentScan: () => void;
}

export const useScanStore = create<ScanStore>((set) => ({
  currentScan: null,
  scanHistory: [],
  isScanning: false,
  
  setCurrentScan: (scan) => set({ currentScan: scan }),
  
  updateScan: (updates) => set((state) => ({
    currentScan: state.currentScan 
      ? { ...state.currentScan, ...updates }
      : null
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
  
  addToHistory: (scan) => set((state) => ({
    scanHistory: [...state.scanHistory, scan]
  })),
  
  setIsScanning: (status) => set({ isScanning: status }),
  
  clearCurrentScan: () => set({ currentScan: null, isScanning: false })
}));
