import { create } from 'zustand';
import { ScanState, Vulnerability } from '../types/scan.types';

interface ScanStore {
  currentScan: ScanState | null;
  scanHistory: ScanState[];
  isScanning: boolean;
  outputLines: string[];
  
  setCurrentScan: (scan: ScanState | null) => void;
  updateScan: (updates: Partial<ScanState>) => void;
  addFinding: (finding: Vulnerability) => void;
  addFindings: (findings: Vulnerability[]) => void;
  addToHistory: (scan: ScanState) => void;
  setIsScanning: (status: boolean) => void;
  clearCurrentScan: () => void;
  addOutputLine: (line: string) => void;
  clearOutput: () => void;
  updatePhase: (phase: ScanState['phase']) => void;
  updateCoverage: (coverage: number) => void;
}

export const useScanStore = create<ScanStore>((set) => ({
  currentScan: null,
  scanHistory: [],
  isScanning: false,
  outputLines: [],
  
  setCurrentScan: (scan) => set({ currentScan: scan, isScanning: !!scan }),
  
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
    scanHistory: [...state.scanHistory, scan],
    isScanning: false
  })),
  
  setIsScanning: (status) => set({ isScanning: status }),
  
  clearCurrentScan: () => set({ currentScan: null, isScanning: false, outputLines: [] }),

  addOutputLine: (line) => set((state) => ({
    outputLines: [...state.outputLines, line]
  })),

  clearOutput: () => set({ outputLines: [] }),

  updatePhase: (phase) => set((state) => ({
    currentScan: state.currentScan
      ? { ...state.currentScan, phase }
      : null
  })),

  updateCoverage: (coverage) => set((state) => ({
    currentScan: state.currentScan
      ? { ...state.currentScan, coverage }
      : null
  }))
}));
