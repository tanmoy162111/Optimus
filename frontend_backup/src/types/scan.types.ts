export interface Vulnerability {
  name: string;
  type: string;
  severity: number;
  confidence: number;
  evidence: string;
  location: string;
  tool: string;
  exploitable: boolean;
  remediation?: string;
  ml_classified?: boolean;
  pattern_matched?: boolean;
}

export interface ScanState {
  scan_id: string;
  target: string;
  phase: 'reconnaissance' | 'scanning' | 'exploitation' | 'post_exploitation' | 'covering_tracks';
  status: 'initializing' | 'running' | 'paused' | 'completed' | 'stopped' | 'error';
  start_time: string;
  end_time?: string;
  findings: Vulnerability[];
  tools_executed: string[];
  time_elapsed?: number;
  coverage: number;
  risk_score: number;
  ml_confidence?: number;
  phase_data?: Record<string, any>;
}

export interface ScanSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}
