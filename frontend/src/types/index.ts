// ============================================
// Core Types for Optimus Frontend
// ============================================

// Vulnerability Types
export interface Vulnerability {
  id: string;
  name: string;
  type: VulnerabilityType;
  severity: number;
  confidence: number;
  evidence: string;
  location: string;
  tool: string;
  exploitable: boolean;
  remediation?: string;
  cve?: string;
  cwe?: string;
  references?: string[];
  timestamp: string;
  ml_classified?: boolean;
  pattern_matched?: boolean;
}

export type VulnerabilityType = 
  | 'sql_injection'
  | 'xss'
  | 'rce'
  | 'lfi'
  | 'rfi'
  | 'ssrf'
  | 'xxe'
  | 'csrf'
  | 'idor'
  | 'auth_bypass'
  | 'info_disclosure'
  | 'misconfig'
  | 'outdated_software'
  | 'weak_crypto'
  | 'other';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Scan Types
export interface Scan {
  scan_id: string;
  target: string;
  domain?: string;
  host?: string;
  phase: ScanPhase;
  status: ScanStatus;
  start_time: string;
  end_time?: string;
  findings: Vulnerability[];
  tools_executed: ToolExecution[];
  time_elapsed: number;
  coverage: number;
  risk_score: number;
  ml_confidence?: number;
  phase_data?: Record<string, PhaseData>;
  options?: Record<string, any>;
  exploits_attempted?: any[];
  sessions_obtained?: any[];
  credentials_found?: any[];
  discovered_endpoints?: any[];
  discovered_technologies?: any[];
  open_ports?: any[];
  stop_requested?: boolean;
  clients?: number;
  error?: string;
  config?: Record<string, any>;
  technologies_detected?: string[];
  blacklisted_tools?: string[];
  recently_used_tools?: string[];
  strategy?: string;
  strategy_changes?: number;
  last_finding_iteration?: number;
  phase_start_time?: string;
}

export type ScanPhase = 
  | 'reconnaissance'
  | 'scanning'
  | 'enumeration'
  | 'exploitation'
  | 'post_exploitation'
  | 'reporting';

export type ScanStatus = 
  | 'initializing'
  | 'running'
  | 'paused'
  | 'completed'
  | 'stopped'
  | 'error';

export interface ToolExecution {
  tool: string;
  started_at: string;
  completed_at?: string;
  status: 'running' | 'completed' | 'failed';
  findings_count: number;
  execution_time?: number;
}

export interface PhaseData {
  started_at: string;
  completed_at?: string;
  tools_used: string[];
  findings_count: number;
  coverage: number;
}

// Tool Types
export interface Tool {
  name: string;
  category: ToolCategory;
  description: string;
  version?: string;
  is_available: boolean;
  requires_root: boolean;
  source: 'knowledge_base' | 'discovered' | 'llm_generated' | 'web_research';
  confidence?: number;
}

export type ToolCategory = 
  | 'recon'
  | 'scanning'
  | 'enumeration'
  | 'exploitation'
  | 'post_exploitation'
  | 'password'
  | 'wireless'
  | 'web'
  | 'database'
  | 'forensics'
  | 'reverse_engineering'
  | 'sniffing'
  | 'social_engineering'
  | 'reporting'
  | 'utility';

export interface ToolResolution {
  tool_name: string;
  source: string;
  status: 'resolved' | 'partial' | 'fallback' | 'failed';
  command?: string;
  explanation: string;
  confidence: number;
  help_text?: string;
  examples: string[];
  warnings: string[];
  alternatives: string[];
}

// WebSocket Event Types
export interface WSEvent<T = unknown> {
  type: string;
  scan_id?: string;
  data: T;
  timestamp: string;
}

export interface ScanStartedEvent {
  scan_id: string;
  target: string;
  config?: Record<string, unknown>;
}

export interface PhaseTransitionEvent {
  from: ScanPhase;
  to: ScanPhase;
  reason?: string;
}

export interface ToolOutputEvent {
  tool: string;
  output: string;
  stream: 'stdout' | 'stderr';
}

export interface ToolExecutionEvent {
  tool: string;
  target?: string;
  status: 'start' | 'complete' | 'error';
  execution_time?: number;
  success?: boolean;
  findings_count?: number;
  error?: string;
}

export interface ScanUpdateEvent {
  phase: ScanPhase;
  status: ScanStatus;
  coverage: number;
  time_elapsed: number;
  findings?: Vulnerability[];
  tools_executed?: string[];
}

export interface FindingEvent {
  finding: Vulnerability;
  total_count: number;
}

// API Response Types
export interface ApiResponse<T> {
  data: T;
  success: boolean;
  message?: string;
  error?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// Dashboard Stats
export interface DashboardStats {
  active_scans: number;
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  tools_available: number;
  system_health: 'healthy' | 'degraded' | 'unhealthy';
  last_scan?: Scan;
}

// Report Types
export interface Report {
  report_id: string;
  scan_id: string;
  target: string;
  generated_at: string;
  format: 'json' | 'pdf' | 'html' | 'markdown';
  executive_summary: ExecutiveSummary;
  findings: Vulnerability[];
  recommendations: Recommendation[];
  attack_chain?: AttackChainNode[];
  metadata: ReportMetadata;
}

export interface ExecutiveSummary {
  risk_level: SeverityLevel;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  summary_text: string;
  key_findings: string[];
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  priority: 'immediate' | 'high' | 'medium' | 'low';
  effort: 'low' | 'medium' | 'high';
  related_vulnerabilities: string[];
}

export interface AttackChainNode {
  id: string;
  vulnerability_id: string;
  name: string;
  description: string;
  prerequisites: string[];
  leads_to: string[];
  success_probability: number;
}

export interface ReportMetadata {
  duration_seconds: number;
  tools_used: string[];
  coverage_percentage: number;
  scan_config?: Record<string, unknown>;
}

// Model Types
export interface MLModel {
  id: string;
  name: string;
  type: 'vulnerability_classifier' | 'risk_predictor' | 'tool_selector';
  version: string;
  accuracy: number;
  last_trained: string;
  is_active: boolean;
  metrics: ModelMetrics;
}

export interface ModelMetrics {
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  training_samples: number;
}

// System Types
export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  components: ComponentHealth[];
  uptime_seconds: number;
  memory_usage: number;
  cpu_usage: number;
  active_connections: number;
}

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  message?: string;
  last_check: string;
}

// Notification Types
export interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  action?: {
    label: string;
    url: string;
  };
}

// UI State Types
export interface TerminalLine {
  id: string;
  content: string;
  type: 'input' | 'output' | 'error' | 'info' | 'success' | 'warning';
  timestamp: string;
  tool?: string;
}
